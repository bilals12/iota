package logprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

type Processor struct {
	classifier *Classifier
}

type ProcessedEvent struct {
	Event           *cloudtrail.Event
	LogType         string
	EventTime       time.Time
	ParseTime       time.Time
	RowID           string
}

func New() *Processor {
	return &Processor{
		classifier: NewClassifier(),
	}
}

func (p *Processor) Process(ctx context.Context, reader io.Reader) (<-chan *ProcessedEvent, <-chan error) {
	events := make(chan *ProcessedEvent, 100)
	errs := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errs)

		decoder := json.NewDecoder(reader)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			var rawEvent map[string]interface{}
			if err := decoder.Decode(&rawEvent); err != nil {
				if err == io.EOF {
					return
				}
				continue
			}

			var event cloudtrail.Event
			eventBytes, _ := json.Marshal(rawEvent)
			if err := json.Unmarshal(eventBytes, &event); err != nil {
				continue
			}

			logType := p.classifier.Classify(&event)
			now := time.Now()

			processed := &ProcessedEvent{
				Event:     &event,
				LogType:   logType,
				EventTime: now,
				ParseTime: now,
				RowID:     generateRowID(&event),
			}

			select {
			case events <- processed:
			case <-ctx.Done():
				return
			}
		}
	}()

	return events, errs
}

func generateRowID(event *cloudtrail.Event) string {
	return fmt.Sprintf("%s-%s", event.EventID, event.EventTime.Format("20060102150405"))
}
