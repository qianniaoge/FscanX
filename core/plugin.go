package core

import "FscanX/plugin"

var PluginMap = map[string]interface{}{
	"21":plugin.FTPSCAN,
	"22":plugin.SSHSCAN,
	"135":plugin.OXIDSCAN,
	"139":plugin.NETBIOS,
	"1433":plugin.MSSQLSCAN,
	"3306":plugin.MYSQLSCAN,
	"5432":plugin.POSTGRESCAN,
	"6379":plugin.REDISSCAN,
	"27017":plugin.MONGODBSCAN,
	"eternalblue":plugin.MS17070,
	"smbghost":plugin.SMBGHOST,

}
