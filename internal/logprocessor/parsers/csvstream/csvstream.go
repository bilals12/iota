package csvstream

import (
	"encoding/csv"
	"io"
)

type StreamingCSVReader struct {
	CVSReader *csv.Reader
	logLine   string
}

func NewStreamingCSVReader() *StreamingCSVReader {
	scr := &StreamingCSVReader{}
	reader := csv.NewReader(scr)
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = true
	reader.LazyQuotes = true
	scr.CVSReader = reader
	return scr
}

func (scr *StreamingCSVReader) Read(b []byte) (n int, err error) {
	n = copy(b, scr.logLine)
	if n < len(scr.logLine) {
		scr.logLine = scr.logLine[n:]
		return n, nil
	}
	scr.logLine = ""
	return n, io.EOF
}

func (scr *StreamingCSVReader) Parse(log string) ([]string, error) {
	scr.logLine = log
	return scr.CVSReader.Read()
}
