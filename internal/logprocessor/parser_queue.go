package logprocessor

import (
	"container/heap"

	"github.com/bilals12/iota/internal/logprocessor/parsers"
)

type ParserPriorityQueue struct {
	items []*ParserQueueItem
}

func NewParserPriorityQueue(parserMap map[string]parsers.ParserInterface) *ParserPriorityQueue {
	q := &ParserPriorityQueue{}
	q.initialize(parserMap)
	heap.Init(q)
	return q
}

func (q *ParserPriorityQueue) initialize(parserMap map[string]parsers.ParserInterface) {
	for logType, parser := range parserMap {
		q.items = append(q.items, &ParserQueueItem{
			logType: logType,
			parser:  parser,
			penalty: 1,
		})
	}
}

type ParserQueueItem struct {
	logType string
	parser  parsers.ParserInterface
	penalty int
	index   int
}

func (q *ParserPriorityQueue) Len() int {
	return len(q.items)
}

func (q *ParserPriorityQueue) Less(i, j int) bool {
	return q.items[i].penalty < q.items[j].penalty
}

func (q *ParserPriorityQueue) Swap(i, j int) {
	q.items[i], q.items[j] = q.items[j], q.items[i]
	q.items[i].index = i
	q.items[j].index = j
}

func (q *ParserPriorityQueue) Push(x interface{}) {
	n := len(q.items)
	item := x.(*ParserQueueItem)
	item.index = n
	q.items = append(q.items, item)
}

func (q *ParserPriorityQueue) Pop() interface{} {
	n := len(q.items)
	item := q.items[n-1]
	q.items[n-1] = nil
	item.index = -1
	q.items = q.items[0 : n-1]
	return item
}

func (q *ParserPriorityQueue) Peek() *ParserQueueItem {
	if len(q.items) == 0 {
		return nil
	}
	return q.items[0]
}

func (q *ParserPriorityQueue) Update(item *ParserQueueItem, penalty int) {
	item.penalty = penalty
	heap.Fix(q, item.index)
}

func (q *ParserPriorityQueue) FindByLogType(logType string) *ParserQueueItem {
	for _, item := range q.items {
		if item.logType == logType {
			return item
		}
	}
	return nil
}
