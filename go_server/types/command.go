package types

const CMD_TURNOFF_COMPUTER = 	0
const CMD_TAKESCREENSHOT = 		1
const CMD_BLOCK_INPUT =			2
const CMD_GET_KEYBOARD_DATA =	3

const CMD_STATUS_PENDING = 		88      // remote control sent that he wants to perform command
const CMD_STATUS_READYEXECUTE = 89 // client is need to execute
const CMD_STATUS_FINISHED = 	90     // server set this command to be finished after successful executing
const CMD_STATUS_SUCCESS = 		91
const CMD_STATUS_SYSTEM_ERROR = 92

type Command struct {
	IntValue  int     	`json:"cmd_type"`		// the type of command (if used, OsCommand must be null)
	Status    int     	`json:"status"`		// status of command (success, failed)
	OsCommand string 	`json:"os_command"` 	// operating system command executed in shell
	ExitCode  int    	`json:"exit_code"`		// exit code of command
	StreamType int	 	`json:"stream_type"`	// stderr, stdout
	Output		string	`json:"output"`		// what command printed to console screen
}

type CommandContainer struct 
{
	Commands[] *Command
}

func (q * CommandContainer)GetSize() int {
	return len(q.Commands)
}

func (q * CommandContainer)SetElement(value * Command, index int) {

	q.Commands[index] = value
}

func (q * CommandContainer)GetElement(index int) *Command {
	return q.Commands[index]
}

func (q * CommandContainer)AppendCommand(value * Command) {
	q.Commands = append(q.Commands, value)
}

func (q * CommandContainer)RemoveAt(index int) {

	if (index >= q.GetSize() || index < 0) {
		return
	} 

	prt_1 := q.Commands[0:index]
	prt_2 := q.Commands[index + 1:len(q.Commands)]

	var new_vec [] *Command

	new_vec = append(new_vec, prt_1 ...)
	new_vec = append(new_vec, prt_2 ...)

	q.Commands = new_vec
}

func (q * CommandContainer) Clear() {
	clear(q.Commands)
}

func CreateNewReady(cmd_type int) *Command {

	cmd := new(Command)

	cmd.Status = CMD_STATUS_READYEXECUTE
	cmd.IntValue = cmd_type
	cmd.OsCommand = ""
	return cmd
}

func (*Command) SetStatus(status int, cmd *Command) {
	cmd.Status = status
}

func (*Command) GetStatus(cmd *Command) int {
	return cmd.Status
}

func IsWellKnown(cmd_type int) bool {

	switch cmd_type {
	case CMD_TAKESCREENSHOT, CMD_TURNOFF_COMPUTER, CMD_BLOCK_INPUT, CMD_GET_KEYBOARD_DATA:
		return true
	}

	return false
}