package output

import (
	"encoding/json"
	"io"

	"github.com/marteinnlundi/soc-in-a-box/tools/logpipe/internal/schema"
)

type JSONLWriter struct {
	w io.Writer
}

func NewJSONLWriter(w io.Writer) *JSONLWriter {
	return &JSONLWriter{w: w}
}

func (jw *JSONLWriter) WriteEvent(event *schema.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	_, err = jw.w.Write(append(data, '\n'))
	return err
}
