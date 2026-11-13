// logpipe normalises raw log lines (syslog or JSON) read from stdin into
// JSONL events that follow docs/standards/event_schema.md.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/marteinnlundi/soc-in-a-box/tools/logpipe/internal/output"
	"github.com/marteinnlundi/soc-in-a-box/tools/logpipe/internal/processor"
	"github.com/marteinnlundi/soc-in-a-box/tools/logpipe/internal/schema"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

// maxLineBytes is the longest input line logpipe accepts (1 MiB).
const maxLineBytes = 1 << 20

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: logpipe < raw.log > events.jsonl")
		fmt.Fprintln(os.Stderr, "Reads syslog or JSON lines from stdin and writes normalised JSONL events to stdout.")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Println("logpipe", version)
		return
	}

	writer := output.NewJSONLWriter(os.Stdout)

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	skipped := 0
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var event *schema.Event
		var err error

		if line[0] == '{' {
			event, err = processor.ParseJSON(line)
		} else {
			event, err = processor.ParseSyslog(line)
		}

		if err != nil {
			skipped++
			fmt.Fprintf(os.Stderr, "logpipe: skipping line: %v\n", err)
			continue
		}

		if err := writer.WriteEvent(event); err != nil {
			fmt.Fprintf(os.Stderr, "logpipe: write error: %v\n", err)
			os.Exit(1)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "logpipe: read error: %v\n", err)
		os.Exit(1)
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "logpipe: skipped %d unparseable line(s)\n", skipped)
	}
}
