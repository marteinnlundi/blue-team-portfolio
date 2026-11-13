//go:build linux

// ebpf-telemetry loads two eBPF tracepoint programs and prints one JSONL event
// (docs/standards/event_schema.md) per process start and outbound TCP connect.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/marteinnlundi/soc-in-a-box/tools/ebpf-telemetry/bpf"
	"github.com/marteinnlundi/soc-in-a-box/tools/ebpf-telemetry/internal/event"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

// output serialises writes from the two reader goroutines.
type output struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (o *output) write(ev event.Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.enc.Encode(ev); err != nil {
		log.Printf("write event: %v", err)
	}
}

func readCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return event.CmdlineFromProc(data)
}

// usernames caches UID lookups; /etc/passwd rarely changes while we run.
type usernames struct {
	mu    sync.Mutex
	cache map[uint32]string
}

func (u *usernames) lookup(uid uint32) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if name, ok := u.cache[uid]; ok {
		return name
	}
	name := ""
	if account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		name = account.Username
	}
	u.cache[uid] = name
	return name
}

// consume reads records from one ring buffer until it is closed.
func consume(rd *ringbuf.Reader, name string, handle func(raw []byte) error) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("%s ring buffer: %v", name, err)
			continue
		}
		if err := handle(record.RawSample); err != nil {
			log.Printf("%s: %v", name, err)
		}
	}
}

func run() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpf.Object))
	if err != nil {
		return fmt.Errorf("parse embedded BPF object: %w", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit (are you root?): %w", err)
	}

	var objs struct {
		HandleExec    *ebpf.Program `ebpf:"handle_exec"`
		HandleConnect *ebpf.Program `ebpf:"handle_connect"`
		ExecEvents    *ebpf.Map     `ebpf:"exec_events"`
		ConnectEvents *ebpf.Map     `ebpf:"connect_events"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			return fmt.Errorf("kernel rejected the BPF program:\n%+v", verr)
		}
		return fmt.Errorf("load BPF programs (needs root and kernel 5.8+ with BTF): %w", err)
	}
	defer objs.HandleExec.Close()
	defer objs.HandleConnect.Close()
	defer objs.ExecEvents.Close()
	defer objs.ConnectEvents.Close()

	tpExec, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		return fmt.Errorf("attach sched:sched_process_exec: %w", err)
	}
	defer tpExec.Close()

	tpConnect, err := link.Tracepoint("sock", "inet_sock_set_state", objs.HandleConnect, nil)
	if err != nil {
		return fmt.Errorf("attach sock:inet_sock_set_state: %w", err)
	}
	defer tpConnect.Close()

	execRd, err := ringbuf.NewReader(objs.ExecEvents)
	if err != nil {
		return fmt.Errorf("open exec ring buffer: %w", err)
	}
	defer execRd.Close()

	connectRd, err := ringbuf.NewReader(objs.ConnectEvents)
	if err != nil {
		return fmt.Errorf("open connect ring buffer: %w", err)
	}
	defer connectRd.Close()

	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	out := &output{enc: enc}
	names := &usernames{cache: map[uint32]string{}}
	resolver := event.Resolver{Cmdline: readCmdline, Username: names.lookup}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		consume(execRd, "exec", func(raw []byte) error {
			rec, err := event.DecodeExec(raw)
			if err != nil {
				return err
			}
			out.write(event.FromExec(rec, host, time.Now(), resolver))
			return nil
		})
	}()
	go func() {
		defer wg.Done()
		consume(connectRd, "connect", func(raw []byte) error {
			rec, err := event.DecodeConnect(raw)
			if err != nil {
				return err
			}
			ev, err := event.FromConnect(rec, host, time.Now(), resolver)
			if err != nil {
				return err
			}
			out.write(ev)
			return nil
		})
	}()

	log.Println("ebpf-telemetry: watching process starts and outbound TCP connections; Ctrl-C to stop")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	_ = execRd.Close()
	_ = connectRd.Close()
	wg.Wait()
	return nil
}

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("ebpf-telemetry", version)
		return
	}

	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatalf("ebpf-telemetry: %v", err)
	}
}
