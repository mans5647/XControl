package tests

import (
	"fmt"
	"testing"
	"x_server/types"
)


func TestAddCommandsShellManager(t *testing.T) {

	addr := "127.0.0.1"
	sc := types.CreateNewShellCommander()
	
	cmds := []types.Command{
		{Status: types.CMD_STATUS_READYEXECUTE, OsCommand: "ls -la"},
		{Status: types.CMD_STATUS_READYEXECUTE, OsCommand: "type C:\\Users:\\mansu\\somefile"},
	}

	sc.ShellCommanderEnqCommand(&cmds[0], addr)
	sc.ShellCommanderEnqCommand(&cmds[1], addr)

	if (sc.ShellCommanderGetSize(addr) == 0) {
		t.Error("Size")
	}
	
}



func TestAddCommandsForMultipleClientsIsSizesDiffer(t *testing.T) {

	a1 := "243.3.12.2"
	a2 := "185.167.9.2"

	sc := types.CreateNewShellCommander()
	
	a1cmds := []types.Command{
		{Status: types.CMD_STATUS_READYEXECUTE, OsCommand: "ls -la"},
		{Status: types.CMD_STATUS_READYEXECUTE, OsCommand: "type C:\\Users:\\mansu\\somefile"},
		{Status: types.CMD_STATUS_READYEXECUTE, OsCommand: "powershell -C \"ls\""},
	}

	a2cmds := []types.Command{
		{Status: types.CMD_STATUS_SYSTEM_ERROR, OsCommand: "devenv /h"},
		{Status: types.CMD_STATUS_READYEXECUTE, OsCommand: "dir .\\ /a /h"},
	}

	sc.ShellCommanderEnqMultiple(a1, a1cmds...)
	sc.ShellCommanderEnqMultiple(a2, a2cmds...)

	Size1 := sc.ShellCommanderGetSize(a1)
	Size2 := sc.ShellCommanderGetSize(a2)

	if (Size1 == Size2) {
		t.Error("Sizes are equal")
	}

	sc.ShellCommanderDeqCommand(a1)

}

func Test_ShellCommanderUpdateValues_isdiffers(t *testing.T) {

	cmds := []types.Command{
		{Status: types.CMD_STATUS_READYEXECUTE, OsCommand: "ls -la"},
		{Status: types.CMD_STATUS_PENDING, OsCommand: "type C:\\Users:\\mansu\\somefile"},
	}

	var sh types.ShellCommander
	var prevState, newState * types.Command
	// push sample command
	sh.ShellCommanderEnqCommand(&cmds[0], "127.0.0.1")

	prevState = sh.ShellCommanderFirst("127.0.0.1")

	// update by 2'nd value located in array
	sh.UpdateFirst("127.0.0.1", &cmds[1])

	newState = sh.ShellCommanderFirst("127.0.0.1")
	
	if (prevState.OsCommand == newState.OsCommand) {
		t.Error("OsCommand")
	}
	
	fmt.Println(newState)
	fmt.Println(prevState)
}