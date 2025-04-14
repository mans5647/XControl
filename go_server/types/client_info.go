package types

type OSInfo struct 
{
	ID                int64 		`json:"id" gorm:"primaryKey"`
	MemAvailableBytes int64  		`json:"mem_av"`
	MemUsedBytes      int64  		`json:"mem_usd"`
	Uptime		  	  int64			`json:"uptime"`
}

type Client struct 
{
	ID 					int    					`json:"cl_id" gorm:"column:client_id;primaryKey"`
	RemoteAddr  		string 					`json:"remote_addr" gorm:"column:remote_address;"`
	DesktopName       	string 					`json:"desktop_name"`
	UpdateTime			int64					`json:"update_time"`
	Online				bool					`json:"online"`
}

type Process struct 
{
	ProcessId             int64  `json:"process_id"`
	ProcessName           string `json:"process_name"`
	ProcessWorkingSetSize int64 	`json:"process_working_set"`
	ProcessCreateTime     int64  `json:"process_create_time"`
	ProcessUserTime       int64  `json:"process_user_time"`
	ProcessUserName       string `json:"process_user_name"`
	ProcessExePath        string `json:"process_path"`
}