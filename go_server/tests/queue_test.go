package tests


import (
	"x_server/types"
	"testing"
)

func SizesEqual(q1 * types.SimpleQueue, q2 * types.SimpleQueue) bool {

	return q1.Size() == q2.Size()
}

func TestCompareSizesIsEqual(t * testing.T) {

	q1 := types.SimpleQueue{}
	q1.Enqueue(1)
	q1.Enqueue(2)
	q1.Enqueue(60)

	q2 := types.SimpleQueue{}
	q2.Enqueue(1)
	q2.Enqueue(2)
	q2.Enqueue(60)

	t.Run("Compare sizes", func (t * testing.T) {
		if (!SizesEqual(&q1, &q2)) {
			t.Errorf("Sizes are not equal")
		}
	})
}


func TestPrintToStdout(t * testing.T) {

	q1 := types.SimpleQueue{}
	q1.Enqueue(1)
	q1.Enqueue(2)
	q1.Enqueue(60)

	t.Run("Print", func (t * testing.T) {
		q1.PrintElements()
	})

}

func Test_RemoveAddElements_CompareSizesBeforeAfter(t * testing.T) {

	q1 := types.SimpleQueue{}
	

	t.Run("Enque elements", func (t * testing.T) {
		ExpectedSize := 3
		q1.Enqueue(1)
		q1.Enqueue(2)
		q1.Enqueue(60)
		if (q1.Size() != ExpectedSize) {
			t.Error("Add failed")
		}
	})
	
	t.Run("Deque all elements", func (t * testing.T) {
		q1.Dequeue()
		q1.Dequeue()
		q1.Dequeue()

		if (q1.Size() != 0) {
			t.Error("Remove failed")
		}
	})

}

func TestIsFirstElementEqualToExpected(t *testing.T) {

	t.Run("Test is FIFO element is truly value", func(t *testing.T) {

		var q1 * types.SimpleQueue
		var Expected int

		q1 = &types.SimpleQueue{}
		Expected = 100

		q1.Enqueue(100)
		q1.Enqueue(200)
		q1.Enqueue(300)

		Val := q1.Dequeue() // removes first stored element
		ValueReal := Val.(int) // cast to integer

		if (ValueReal != Expected) {
			t.Error("First element queue is not equal to expected")
		}

	})

}

func TestCompareNewSizeIsLessThanOldAfterRemoving50Elems(t *testing.T) {

	q1 := types.SimpleQueue{}
	OldSize := 100
	for i := 0 ; i < OldSize; i++ {
		q1.Enqueue(1)
	}

	// remove 50 elements
	for i := 0; i < 50; i++ {
		q1.Dequeue()
	}

	NewSize := q1.Size()

	t.Run("Test is new size less that old", func(t *testing.T) {

		if (NewSize >= OldSize) {
			t.Error("New size is not less after removing")
		}

	})

}