package core

import (
	"FscanX/config"
	"FscanX/plugin"
	"FscanX/webscan"
	"FscanX/webscan/lib"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

func Scanner(flag config.EnterFlag){

	start := time.Now()
	if flag.ScanTypeMain != "mssql-extend" && flag.ScanTypeMain != "redis-extend" && flag.ScanTypeMain != "ssh-extend"&& flag.ScanHost != ""{
		fmt.Println("OS Name:",runtime.GOOS)
		fmt.Println("PID:",os.Getpid(),"FscanX By SaiRson")
		fmt.Println("")
	}
	switch flag.ScanTypeMain {
	case "mssql-extend":
		mssqlExtend()
		break
	case "redis-extend":
		redisExtend(flag)
		break
	case "ssh-extend":
		sshExtend()
	case "hostscan-netbios":
		netbiosScanner(flag)
		break
	case "hostscan-icmp":
		icmpScanner(flag)
		break
	case "hostscan-smart":
		smartScanner(flag)
		break
	case "hostscan-oxid":
		oxidScanner(flag)
	case "vulscan-ms17010","vulscan-smbghost":
		vulnScanner(flag)
		break
	case "portscan":
		portScanner(flag)
		break
	case "webscan":
		webscanner(flag)
	default:
	}
	if flag.ScanTypeMain != "mssql-extend" && flag.ScanTypeMain != "redis-extend" && flag.ScanTypeMain != "ssh-extend"&& flag.ScanHost != "" {
		elapsed := time.Since(start)
		if elapsed != 0 {
			fmt.Println("=========================================")
			fmt.Println("Scan Finished !")
			fmt.Println("[total time]", elapsed)
		}
	}
}

func mssqlExtend(){
	switch config.MSSQLFLAG.Method {
	case 1:
		plugin.MSSQL_XP_CMD_SHELL(&config.MSSQLFLAG)
		break
	case 2:
		plugin.MSSQL_SP_OACREATE(&config.MSSQLFLAG)
		break
	case 3:
		plugin.INSTALLCLR(&config.MSSQLFLAG)
		break
	case 4:
		plugin.UNINSTALLCLR(&config.MSSQLFLAG)
		break
	default:
		//fmt.Println("[-] not found method for mssql extend")
		config.WriteLogFile(config.LogFile,"[-] not found method for mssql extend",config.Inlog)
		break
	}
}

func redisExtend(flag config.EnterFlag){
	//fmt.Println(flag)
	//fmt.Println(config.REDISFLAG)
	//fmt.Println(config.RedisShell,config.RedisFile)
	plugin.REDISEXTENDSHELL(&config.HostData{
		HostName: config.REDISFLAG.Host,
		TimeOut: 1,
		Ports: config.REDISFLAG.Port,
	})
	//fmt.Println(err)
}

func sshExtend(){
	//err := plugin.SSHSCAN(&config.HostData{HostName: config.SSHFLAG.Host,Ports: config.SSHFLAG.Port,SshKey: config.SSHFLAG.SshKey,Command: config.SSHFLAG.Command})
	//fmt.Println(err)
	//
	//fmt.Println( config.SSHFLAG.Command)
	plugin.SSHEXTENDSHELL(&config.HostData{
		HostName: config.SSHFLAG.Host,
		Ports: config.SSHFLAG.Port,
		SshKey: config.SSHFLAG.SshKey,
		Command: config.SSHFLAG.Command,
	})
}
func netbiosScanner(flag config.EnterFlag){
	if flag.ScanHost == ""{
		return
	}
	ips,_ := ResolveIPS(flag.ScanHost)
	var wg sync.WaitGroup
	var taskchan = make(chan string)
	go func() {
		for _, ip := range ips {
			taskchan <- ip
		}
		defer close(taskchan)
	}()
	for i := 0; i < int(flag.Thread); i++ {
		wg.Add(1)
		go func(taskchan chan string) {
			defer wg.Done()
			for ip := range taskchan {
				_,status,msg := plugin.NETBIOS(&config.HostData{HostName: ip,Ports: 139})
				if status == true{
					config.WriteLogFile(config.LogFile,msg,config.Inlog)
				}
			}
		}(taskchan)
	}
	wg.Wait()
}

func icmpScanner(flag config.EnterFlag){
	if flag.ScanHost == ""{
		return
	}
	ips,_ := ResolveIPS(flag.ScanHost)
	alivePC := plugin.ICMPSCAN(flag.Thread,ips,!flag.Noping)
	for _,value := range alivePC{
		config.WriteLogFile(config.LogFile,fmt.Sprintf("[*] %v",value),config.Inlog)
	}
}

func smartScanner(flag config.EnterFlag){
	if flag.ScanHost == ""{
		return
	}
	ips,_ := ResolveIPS(flag.ScanHost)
	alivePC := plugin.RETRUNALIVE(flag.Thread,ips)
	for _,value := range alivePC{
		config.WriteLogFile(config.LogFile,fmt.Sprintf("[*] %v",value),config.Inlog)
	}
}

func vulnScanner(flag config.EnterFlag){
	if flag.ScanHost == ""{
		return
	}
	ips ,_ := ResolveIPS(flag.ScanHost)
	//fmt.Println(ips)
	plugin.VULNSCAN(flag.Thread,ips,flag.ScanTypeMain)
}

func portScanner(flag config.EnterFlag){
	//var result []config.PortResult
	//ips, _ :=  ResolveIPS(flag.ScanHost)
	if flag.ScanHost == ""{
		return
	}
	var resolveports []int
	if flag.Ports != "" {
		resolveports = RemoveDuplicate(resolvePorts(flag.Ports)) // 解析要扫描的端口
	}else{
		resolveports = config.DefaultPorts
	}
	//fmt.Println(flag)
	//fmt.Println(resolveports)
	ips,_ := ResolveIPS(flag.ScanHost) // 获取ip列表，准备扫描端口
	_ = ips
	// 对服务进行分割
	var prarms []string

	if flag.Fragile == "all" {
		prarms = strings.Split("mssql,mysql,redis,mongodb,postgre,ssh,ftp",",")
	}else if flag.Fragile == "nil" {
		prarms = []string{}
	}else{
		prarms = strings.Split(flag.Fragile,",")
	}
	result := plugin.PortScan(flag.Thread,resolveports,ips) // 扫描端口,并获取扫描结果，格式为ip、ports
	var wg sync.WaitGroup
	var taskchan = make(chan config.PortResult)
	go func() {
		for _, scan := range result {
			taskchan <- scan
		}
		defer close(taskchan)
	}()
	for i := 0; i < int(flag.Thread); i++ {
		wg.Add(1)
		go func(taskchan chan config.PortResult) {
			for scan := range taskchan {
				if len(scan.Port) != 0 {
					PORTVULSCAN(scan,prarms)
				}else{
					continue
				}
			}
			wg.Done()
		}(taskchan)
	}
	wg.Wait()
}



func PORTVULSCAN(result config.PortResult,prarms []string){
	// 这里速度会慢，但是没解决方法，所以这里打算采用并发的方式
	// 这里便利所有扫描到的ip,port
	config.WriteLogFile(config.LogFile,fmt.Sprintf("[*] %s %v",result.IP,result.Port),config.Inlog) // 输出
	// 执行脆弱服务扫描
	if len(result.Port) != 0 && len(prarms)!=0 {
		for _,port := range result.Port{
			for _,scantype := range prarms{ //循环类型，如果类型满足，且端口满足
				switch{
					case strings.ToLower(scantype) == "mssql" && port == 1433:
						_ = FuncCall(PluginMap,"1433",&config.HostData{HostName: result.IP,Ports: 1433})
					case strings.ToLower(scantype) == "mysql" && port == 3306:
						_ = FuncCall(PluginMap,"3306",&config.HostData{HostName: result.IP,Ports: 3306})
					case strings.ToLower(scantype) == "ftp" && port == 21:
						_ = FuncCall(PluginMap,"21",&config.HostData{HostName: result.IP,Ports: 21})
					case strings.ToLower(scantype) == "ssh" && port == 22:
						_ = FuncCall(PluginMap,"22",&config.HostData{HostName: result.IP,Ports: 22,SshKey: "",Command: ""})
					case strings.ToLower(scantype) == "redis" && port == 6379:
						_ = FuncCall(PluginMap,"6379",&config.HostData{HostName: result.IP,Ports: 6379,SshKey: "",Command: ""})
					case strings.ToLower(scantype) == "postgre" && port == 5432:
						_ = FuncCall(PluginMap,"5432",&config.HostData{HostName: result.IP,Ports: 5432,SshKey: "",Command: ""})
					case strings.ToLower(scantype) == "mongodb" && port == 27017:
						_ = FuncCall(PluginMap,"27017",&config.HostData{HostName: result.IP,Ports: 27017,SshKey: "",Command: ""})
					default:
						continue
				}
			}
		}
	}
}


func oxidScanner(flag config.EnterFlag){
	if flag.ScanHost == ""{
		return
	}
	ips, _ :=  ResolveIPS(flag.ScanHost)
	var wg sync.WaitGroup
	var taskchan = make(chan string)
	go func() {
		for _, ip := range ips {
			taskchan <- ip
		}
		defer close(taskchan)
	}()
	for i := 0; i < int(flag.Thread); i++ {
		wg.Add(1)
		go func(taskchan chan string) {
			defer wg.Done()
			for ip := range taskchan {
				_ = FuncCall(PluginMap, "135", &config.HostData{HostName: ip, TimeOut: 1, Ports: 135})
			}
		}(taskchan)
	}
	wg.Wait()

}

func webscanner(flag config.EnterFlag){
	lib.Inithttp(config.WebConfig)
	ips, _ :=  ResolveIPS(flag.ScanHost)
	var result []config.PortResult
	//fmt.Println(ips)
	var resolveports []int
	if flag.Ports != "" {
		resolveports = resolvePorts(flag.Ports)
	}else{
		resolveports = config.WebPorts
	}
	result = plugin.PortScan(flag.Thread,resolveports,ips)
	var wg sync.WaitGroup
	var taskchan = make(chan config.PortResult)
	go func() {
		for _,value := range result {
			taskchan <- value
		}
		defer close(taskchan)
	}()
	for i:=0;i<int(flag.Thread);i++{
		wg.Add(1)
		go func(chan config.PortResult) {
			for value := range taskchan{
				if len(value.Port) != 0 {
					//fmt.Println(value)
					webscan.WebScan(&value,flag.FragileBool,int(flag.Thread))
				}else{
					continue
				}
			}
			defer wg.Done()
		}(taskchan)
	}
	wg.Wait()
}