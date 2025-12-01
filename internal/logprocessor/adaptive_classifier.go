package logprocessor

import (
	"container/heap"
	"fmt"
	"strings"
	"time"

	"github.com/bilals12/iota/internal/logprocessor/parsers"
	"github.com/bilals12/iota/pkg/cloudtrail"
)

type AdaptiveClassifier struct {
	parsers     *ParserPriorityQueue
	stats       ClassifierStats
	parserStats map[string]*ParserStats
}

type ClassifierResult struct {
	Events  []*cloudtrail.Event
	Matched bool
	LogType string
	NumMiss int
}

type ClassifierStats struct {
	ClassifyTimeMicroseconds    uint64
	BytesProcessedCount         uint64
	LogLineCount                uint64
	EventCount                  uint64
	SuccessfullyClassifiedCount uint64
	ClassificationFailureCount  uint64
}

type ParserStats struct {
	ParserTimeMicroseconds uint64
	BytesProcessedCount    uint64
	LogLineCount           uint64
	EventCount             uint64
	LogType                string
}

func NewAdaptiveClassifier(parserMap map[string]parsers.ParserInterface) *AdaptiveClassifier {
	return &AdaptiveClassifier{
		parsers:     NewParserPriorityQueue(parserMap),
		parserStats: make(map[string]*ParserStats),
	}
}

func (c *AdaptiveClassifier) Stats() *ClassifierStats {
	return &c.stats
}

func (c *AdaptiveClassifier) ParserStats() map[string]*ParserStats {
	return c.parserStats
}

func safeLogParse(logType string, parser parsers.ParserInterface, log string) (results []*cloudtrail.Event, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parser %q panic: %v", logType, r)
			results = nil
		}
	}()
	results, err = parser.ParseLog(log)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func (c *AdaptiveClassifier) Classify(log string) (*ClassifierResult, error) {
	startClassify := time.Now().UTC()
	var popped []interface{}
	result := &ClassifierResult{}

	if len(log) == 0 {
		return result, nil
	}

	defer func() {
		c.stats.ClassifyTimeMicroseconds = uint64(time.Since(startClassify).Microseconds())
		c.stats.BytesProcessedCount += uint64(len(log))
		c.stats.LogLineCount++
		if result.Matched {
			c.stats.SuccessfullyClassifiedCount++
			c.stats.EventCount += uint64(len(result.Events))
		} else if result.NumMiss != 0 {
			c.stats.ClassificationFailureCount++
		}
	}()

	log = strings.TrimSpace(log)
	if len(log) == 0 {
		return result, nil
	}

	for c.parsers.Len() > 0 {
		currentItem := c.parsers.Peek()

		startParseTime := time.Now().UTC()
		logType := currentItem.logType
		parsedEvents, err := safeLogParse(logType, currentItem.parser, log)
		endParseTime := time.Now().UTC()

		if err != nil {
			poppedItem := heap.Pop(c.parsers).(*ParserQueueItem)
			popped = append(popped, poppedItem)
			c.parsers.Update(poppedItem, poppedItem.penalty+1)
			result.NumMiss++
			continue
		}

		result.Matched = true
		c.parsers.Update(currentItem, 0)
		result.Events = parsedEvents
		result.LogType = logType

		parserStat, exists := c.parserStats[logType]
		if !exists {
			parserStat = &ParserStats{
				LogType: logType,
			}
			c.parserStats[logType] = parserStat
		}
		parserStat.ParserTimeMicroseconds += uint64(endParseTime.Sub(startParseTime).Microseconds())
		parserStat.BytesProcessedCount += uint64(len(log))
		parserStat.LogLineCount++
		parserStat.EventCount += uint64(len(result.Events))
		break
	}

	for _, item := range popped {
		heap.Push(c.parsers, item)
	}

	if !result.Matched {
		return result, fmt.Errorf("failed to classify log line")
	}

	return result, nil
}
