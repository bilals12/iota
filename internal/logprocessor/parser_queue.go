package logprocessor

import (
	"container/heap"
)

type ParserPriorityQueue struct {
	items []*ParserQueueItem
}

func NewParserPriorityQueue(parsers map[string]ParserInterface) *ParserPriorityQueue {
	q := &ParserPriorityQueue{}
	q.initialize(parsers)
	heap.Init(q)
	return q
}

func (q *ParserPriorityQueue) initialize(parsers map[string]ParserInterface) {
	for logType, parser := range parsers {
		q.items = append(q.items, &ParserQueueItem{
			logType: logType,
			parser:  parser,
			penalty: 1,
		})
	}
}

type ParserQueueItem struct {
	logType string
	parser  ParserInterface
	penalty int
}

func (q *ParserPriorityQueue) Len() int {
	return len(q.items)
}

func (q *ParserPriorityQueue) Less(i, j int) bool {
	return q.items[i].penalty < q.items[j].penalty
}

func (q *ParserPriorityQueue) Swap(i, j int) {
	q.items[i], q.items[j] = q.items[j], q.items[i]
}

func (q *ParserPriorityQueue) Push(x interface{}) {
	q.items = append(q.items, x.(*ParserQueueItem))
}

func (q *ParserPriorityQueue) Pop() interface{} {
	n := len(q.items)
	item := q.items[n-1]
	q.items[n-1] = nil
	q.items = q.items[0 : n-1]
	return item
}

func (q *ParserPriorityQueue) Peek() *ParserQueueItem {
	if len(q.items) == 0 {
		return nil
	}
	return q.items[0]
}

func (q *ParserPriorityQueue) Update(item *ParserQueueItem) {
	for i, it := range q.items {
		if it == item {
			heap.Fix(q, i)
			break
		}
	}
}
