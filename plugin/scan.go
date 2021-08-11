package plugin

import (
	"FscanX/config"
	"strings"
	"sync"
)

// icmp扫描存活主机，默认采用icmp协议，如果失败。则采用ping命令


func ICMPSCAN(thread int64,hostlist []string,isping bool)[]string{
	var OnlinePC []string
	var wg sync.WaitGroup
	var hostchan = make(chan string)
	go func() {
		for _,ip := range hostlist{
			hostchan <- ip
		}
		defer close(hostchan)
	}()

	for i:=0;i<int(thread);i++{
		wg.Add(1)
		go func(hostchan chan string){
			defer wg.Done()
			for ip := range hostchan{
				if !execicmp(ip) && isping == true {
					if execping(ip) {
						OnlinePC = append(OnlinePC,ip)
					}
				}else if !execping(ip) && isping == false{

					continue
				}else{
					OnlinePC = append(OnlinePC,ip)
				}
			}
		}(hostchan)
	}
	wg.Wait()
	return OnlinePC
}

func RETRUNALIVE(thread int64,hostlist []string)[]string{
	var OnlinePC []string
	var wg sync.WaitGroup
	var hostchan = make(chan string)
	go func() {
		for _,ip := range hostlist{
			hostchan <- ip
		}
		defer close(hostchan)
	}()

	for i:=0;i<int(thread);i++{
		wg.Add(1)
		go func(hostchan chan string){
			defer wg.Done()
			for ip := range hostchan{
				err,status,_ := NETBIOS(&config.HostData{HostName: ip,Ports: 139})
				//fmt.Println(err)
				if err != nil  && strings.Contains(err.Error(),"timeout") {
					if TCPSCAN(ip) == true {
						//fmt.Println(OnlinePC)
						OnlinePC = append(OnlinePC,ip)
					}
				}else{
					if status == true {
						OnlinePC = append(OnlinePC, ip)
					}
				}
			}
		}(hostchan)
	}
	wg.Wait()
	return OnlinePC
}


func VULNSCAN(thread int64,hostlist []string,vulnType string){
	var wg sync.WaitGroup
	var hostchan = make(chan string)
	go func() {
		for _,ip := range hostlist{
			hostchan <- ip
		}
		defer close(hostchan)
	}()

	for i:=0;i<int(thread);i++{
		wg.Add(1)
		go func(hostchan chan string){
			defer wg.Done()
			for ip := range hostchan{
				switch vulnType {
				case "vulscan-ms17010":
					MS17070(&config.HostData{HostName: ip,Ports: 445})
				case "vulscan-smbghost":
					SMBGHOST(&config.HostData{HostName: ip,Ports: 445})
				}
			}
		}(hostchan)
	}
	wg.Wait()
}
