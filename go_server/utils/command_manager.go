package utils

import (
	"sync"
	"x_server/types"
)

const ERR_NO_ERR = 0
const ERR_NO_CONTAINER_SET = -99
const ERR_NO_SUCH_COMMAND = -98


type SynchronizedCommandsMap struct
{	
	locker sync.Mutex
	data map[string]*types.CommandContainer
}

func (q * SynchronizedCommandsMap) MapLock() {
	q.locker.Lock()
}
func (q * SynchronizedCommandsMap) MapUnlock() {
	q.locker.Unlock()
}


var MyMap = SynchronizedCommandsMap{data: make(map[string]*types.CommandContainer)}


func CreateNewCommandStorage(client_addr string) bool {
	
	MyMap.locker.Lock()

	defer MyMap.locker.Unlock()
	
	MyMap.data[client_addr] = &types.CommandContainer{}
	return true;
}

func PushNewCommandToStorage(cmd * types.Command, client_addr string) bool {

	MyMap.MapLock()

	defer MyMap.MapUnlock()

	cmd_container, ok := MyMap.data[client_addr]

	if (!ok) {
		return false
	}

	cmd_container.AppendCommand(cmd)
	MyMap.data[client_addr] = cmd_container

	return true
}

func GetCommandByClientAddr(client_addr string, cmd_type int) (*types.Command , int) {

	cmd_container, ok := MyMap.data[client_addr]

	if (!ok) {
		return nil, ERR_NO_CONTAINER_SET
	}

	for i := range cmd_container.GetSize() {

		if (cmd_container.Commands[i].IntValue == cmd_type) {
			return cmd_container.Commands[i], ERR_NO_ERR
		}

	} 
	
	return nil, ERR_NO_SUCH_COMMAND
}

func UpdateCommandByClientAddr(client_addr * string, cmd_type int, new_state * types.Command) bool {

	MyMap.locker.Lock()
	defer MyMap.locker.Unlock()

	cmd, err := GetCommandByClientAddr(*client_addr, cmd_type)


	if (err != ERR_NO_ERR) {
		return false
	}

	cmd.IntValue = new_state.IntValue
	cmd.OsCommand = new_state.OsCommand
	cmd.Status = new_state.Status
	return true

}

func GetClientContainer(client_addr * string) *types.CommandContainer {

	data, ok := MyMap.data[*client_addr]
	if (ok) {
		return data
	}

	return nil
}


func DeleteCommandByClientAddr(client_addr * string, cmd_type int) int {

	MyMap.MapLock()
	defer MyMap.MapUnlock()

	container := GetClientContainer(client_addr)

	size := container.GetSize()
	if (size == 0) {
		return -1
	}

	for i := 0; i < size; i++ {

		if (container.GetElement(i).IntValue == cmd_type) {
			container.RemoveAt(i)
			return i
		}

	}


	return -1
}

func IsStorageForClientExists(client_addr * string) bool {
	_, ok := MyMap.data[*client_addr]
	return ok
}

func IsSuchCommandAlreadyInCommandList(client_addr * string, cmd_type int) bool {

	container, ok := MyMap.data[*client_addr]

	if (!ok) { return false }

	for i := range container.GetSize() {

		if (container.Commands[i].IntValue == cmd_type) {
			return true
		}

	}

	return false
}

func RemoveAllClientCommands(client_addr * string) bool {

	container, ok := MyMap.data[*client_addr]

	if (!ok) {
		return false
	}

	container.Clear()

	return true
}

func RemoveClientContainer(client_addr * string) bool {

	_, ok := MyMap.data[*client_addr]

	if (!ok) {
		return false
	}

	delete(MyMap.data, *client_addr)

	return true
}

