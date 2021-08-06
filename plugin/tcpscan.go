package plugin

func TCPSALIVE(ip string) bool {
	var defaultPort = []int{135,139,445,22}
	for _,value := range defaultPort{
		if portconnect(ip,value) == true{
			return true
		}
	}
	return false
}
