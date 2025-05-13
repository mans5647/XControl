package types

import (
	"container/list"
	"fmt"
	"sync"
)

// represents FIFO queue as doubly linked list
type SimpleQueue struct
{
	mu sync.Mutex
	data list.List
}


// pushes item at end of queue
func (sq * SimpleQueue) Enqueue(v any) {
	
	sq.mu.Lock()
	defer sq.mu.Unlock()
	
	sq.data.PushBack(v)
}

// removes item from front of queue and returns it (if empty, returns nil)
func (sq * SimpleQueue) Dequeue() any {

	sq.mu.Lock()
	defer sq.mu.Unlock()

	if (sq.IsEmpty()) { return nil }

	elem :=  sq.data.Front()
	data_any := elem.Value
	sq.data.Remove(elem)
	return data_any
}

// prints elements to stdout
func (sq * SimpleQueue)PrintElements() {

	sq.mu.Lock()
	defer sq.mu.Unlock()

	head := sq.data.Front()
	for p := head; p != nil; p = p.Next() {
		fmt.Println(p.Value)
	}
}

// returns size of queue
func (sq * SimpleQueue)Size() int {
	return sq.data.Len()
}


// access first element
func (sq * SimpleQueue) Front() any {
	return sq.data.Front().Value
}

func (sq * SimpleQueue) IsEmpty() bool {
	return sq.Size() == 0
}

func (sq * SimpleQueue) SetFirst(obj any) {
	sq.data.Front().Value = obj
}

func (sq * SimpleQueue)Clear() {
	sq.data.Init()
}