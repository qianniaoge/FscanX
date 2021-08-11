package webscan

import (
	"FscanX/config"
	"FscanX/webscan/lib"
	"crypto/rand"
	"embed"
	"fmt"
	"math/big"
	"net/http"
	"strings"
)

//go:embed pocs
var Pocs embed.FS

func WebScanPOC(info *httpdata) {
	var pocinfo = config.WebConfig
	buf := strings.Split(info.Host, "/")
	pocinfo.Target = strings.Join(buf[:3], "/")
	if pocinfo.PocName != "" {
		Execute(pocinfo,info.Thread)
		return
	}
	for _, infostr := range info.Infostr {
		pocinfo.PocName = lib.CheckInfoPoc(infostr)
		Execute(pocinfo,info.Thread)
	}
}

func RandUA()string{
	result,_ := rand.Int(rand.Reader,big.NewInt(int64(len(config.DefaultUA))))
	return config.DefaultUA[result.Int64()]
}
func Execute(PocInfo config.WebInfo,thread int) {
	req, err := http.NewRequest("GET", PocInfo.Target, nil)
	if err != nil {
		errlog := fmt.Sprintf("[-] webtitle %v %v", PocInfo.Target, err)
		_ = errlog
		return
	}
	req.Header.Set("User-agent", RandUA())
	if PocInfo.SetCookie != "" {
		req.Header.Set("Cookie", PocInfo.SetCookie)
	}
	lib.CheckMultiPoc(req, Pocs,thread, PocInfo.PocName)
}