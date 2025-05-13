package types

import (
	"sync"
)

// safe hashmap wrapper for client address and queue assigned to it
type ShellCommander struct
{
	addressToQueue sync.Map // mapping for string (address) -> to types.SimpleQueue (queue of commands)
}


// creates new shell commander
func CreateNewShellCommander() * ShellCommander {

	shcmd := new(ShellCommander)
	return shcmd
}
// adds command to client queue
func (sc * ShellCommander) ShellCommanderEnqCommand(cmd * Command, addr string) {

	// loads queue for client address
	cmdQueueAny, ok := sc.addressToQueue.Load(addr)

	// if no such key found, create queue for key
	if (!ok) {
		newQueue := new(SimpleQueue)
		sc.addressToQueue.Store(addr, newQueue)
		cmdQueueAny = newQueue // assign pointer to new memory
	}

	// enqueue command
	cmdQueueRealPtr := cmdQueueAny.(*SimpleQueue)
	cmdQueueRealPtr.Enqueue(cmd)
}

func (sc * ShellCommander) ShellCommanderEnqMultiple(addr string, cmds ... Command) {

	for i := 0; i < len(cmds); i++ {
		sc.ShellCommanderEnqCommand(&cmds[i], addr)
	}

}

// removes command to client queue
func (sc * ShellCommander)ShellCommanderDeqCommand(addr string) bool {

	// loads queue for client address
	cmdQueueAny, ok := sc.addressToQueue.Load(addr)

	if (!ok) { return false }

	// dequeues command from begin of queue
	cmdQueueRealPtr := cmdQueueAny.(*SimpleQueue)
	cmdQueueRealPtr.Dequeue()
	
	return true
}

// gets oldest (first value) from client's queue
func (sc * ShellCommander)ShellCommanderFirst(addr string) (cmd * Command) {

	// loads queue for client address
	cmdQueueAny, ok := sc.addressToQueue.Load(addr)

	// nil, if not found
	if (!ok) {return nil }


	cmdQueueRealPtr := cmdQueueAny.(*SimpleQueue)

	// nil if queue empty
	if (cmdQueueRealPtr.IsEmpty()) { return nil }

	cmdAny := cmdQueueRealPtr.Front()
	
	cmd = cmdAny.(*Command)
	return
}

func (sc * ShellCommander)UpdateFirst(addr string, cmdNewState * Command) bool {

	// loads queue for client address
	cmdQueueAny, ok := sc.addressToQueue.Load(addr)

	if (!ok) {return false }

	cmdQueueRealPtr := cmdQueueAny.(*SimpleQueue)
	cmdQueueRealPtr.SetFirst(cmdNewState)

	return true
}

func (sc * ShellCommander)ShellCommanderGetSize(addr string) int {

	// loads queue for client address
	cmdQueueAny, ok := sc.addressToQueue.Load(addr)

	if (!ok) {return 0}

	cmdQueueRealPtr := cmdQueueAny.(*SimpleQueue)
	return cmdQueueRealPtr.Size()
}

func (sc * ShellCommander)Print(addr string) {

	cmdQueueAny, ok := sc.addressToQueue.Load(addr)

	if (!ok) {return}

	cmdQueueRealPtr := cmdQueueAny.(*SimpleQueue)
	cmdQueueRealPtr.PrintElements()
}

func (sc * ShellCommander)Clear(addr string) bool {

	cmdQueueAny, ok := sc.addressToQueue.Load(addr)

	if (!ok) {return false}
	
	cmdQueueRealPtr := cmdQueueAny.(*SimpleQueue)
	cmdQueueRealPtr.Clear()
	
	return true
}