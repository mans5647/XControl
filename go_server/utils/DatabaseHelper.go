package utils

import 
(
	"errors"
	"time"
	"x_server/types"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const CLIENT_NEW 		 = 0
const CLIENT_UPD 		 = 1
const CLIENT_EXIST 		 = 2
const CLIENT_ADD_OK 	 = 3
const CLIENT_ADD_FAILURE = 4

const conn_str = "host=database user=postgres password=password123 dbname=x_db port=5432 sslmode=disable"

func GetNewDbClient() *gorm.DB {

	db, err := gorm.Open(postgres.Open(conn_str), &gorm.Config{});

	if (err != nil) {
		return nil;
	}

	return db;
}

func MakeMigrations(db_conn * gorm.DB) bool {

	db_conn.AutoMigrate(types.Client{})
	return true;
}

func client_exists(ins * gorm.DB, id int) bool {

	client := types.Client{}
	err := ins.First(&types.Client{ID: id}).First(&client).Error

	return !(errors.Is(err, gorm.ErrRecordNotFound))
}

func client_exists_ip(db * gorm.DB, ip string) bool {

	client := types.Client{};
	err := db.Where(&types.Client{RemoteAddr: ip}).First(&client).Error
	return !(errors.Is(err, gorm.ErrRecordNotFound))
}

func AddClientDB(ins * gorm.DB, client * types.Client, id * int, ip string) (*types.Client, int) {

	if (client_exists_ip(ins, ip)) {
		return FindClientByIpAddrDB(ins, ip), CLIENT_EXIST
	}


	client.UpdateTime = time.Now().Unix()
	client.RemoteAddr = ip

	err := ins.Create(client).Error
	if (err != nil) {
		return nil, CLIENT_ADD_FAILURE
	}

	*id = client.ID

	return client, CLIENT_ADD_OK
}

func UpdateClientDB(ins * gorm.DB, client * types.Client) bool {
	err := ins.Save(client).Error
	return err == nil;
}

func FindClientByIdDB(ins * gorm.DB, id_ int) * types.Client {
	value := types.Client{}
	err := ins.Where(&types.Client{ID: id_}).First(&value).Error
	if (err != nil) { return nil }
	return &value
}

func FindClientByIpAddrDB(ins * gorm.DB, addr string) * types.Client {

	cl := types.Client{};
	err_search := ins.Where(&types.Client{RemoteAddr: addr}).First(&cl).Error

	if (errors.Is(err_search, gorm.ErrRecordNotFound)) {
		return nil
	}

	return &cl;
}


func GetAllRegisteredClients(db * gorm.DB) ([]types.Client, error) {

	var clients []types.Client
	err := db.Model(&types.Client{}).Find(&clients).Error

	if (err == nil) {
		return clients, nil
	}

	return nil, err
}

func SetClientOnlineStatus(db * gorm.DB) {

	

}