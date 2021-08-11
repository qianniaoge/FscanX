package plugin

import (
	"sync"
)

func TCPSCAN(host string) bool {
	var tcp = []int{21,22,135,139,445,25,53}
	return toscanOneports(7,tcp,host)
}

func toscanOneports(thread int64,ports []int,ip string)bool{
	var status  = false
	if len(ports) != 0 {
		var portchan = make(chan int)
		var wg sync.WaitGroup
		go func() {
			for _, port := range ports{
				portchan <- port
			}
			defer close(portchan)
		}()
		for i:=0;i<int(thread);i++ {
			wg.Add(1)
			go func(portschan chan int) {
				for port := range portchan{
					if portconnect(ip,port) == true {
						status = true
						break
					}
				}
				wg.Done()
			}(portchan)
		}
		wg.Wait()
	}
	return status
}