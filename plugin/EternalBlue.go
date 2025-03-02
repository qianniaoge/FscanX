package plugin

import (
	"FscanX/config"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var(
	negotiateProtocolRequest, _  = hex.DecodeString("00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
	sessionSetupRequest, _       = hex.DecodeString("00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
	treeConnectRequest, _        = hex.DecodeString("00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
	transNamedPipeRequest, _     = hex.DecodeString("0000004aff534d42250000000018012800000000000000000000000000088ea3010852981000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00")
	trans2SessionSetupRequest, _ = hex.DecodeString("0000004eff534d4232000000001807c00000000000000000000000000008fffe000841000f0c0000000100000000000000a6d9a40000000c00420000004e0001000e000d0000000000000000000000000000")
)

func ms17070Scan(info *config.HostData) error {
	var addr = fmt.Sprintf("%s:%v",info.HostName,445)
	conn, err := net.DialTimeout("tcp",addr,time.Duration(info.TimeOut)*time.Second)
	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Close()
	}()
	err = conn.SetDeadline(time.Now().Add(time.Duration(info.TimeOut)*time.Second))
	if err != nil{
		return err
	}
	_ , err = conn.Write(negotiateProtocolRequest)
	if err != nil {
		return err
	}
	var reply = make([]byte,1024)
	n, err := conn.Read(reply)
	if err != nil || n < 36 {
		return err
	}
	if binary.LittleEndian.Uint32(reply[9:13]) != 0{
		return err
	}
	_, err = conn.Write(sessionSetupRequest)
	if err != nil {
		return err
	}
	n, err = conn.Read(reply)
	if err != nil || n < 36{
		return err
	}
	if binary.LittleEndian.Uint32(reply[9:13]) !=0 {
		return errors.New("can't determine whether target is vulnerable or not")
	}
	var os string
	var sessionSetupResponse = reply[36:n]
	if wordCount := sessionSetupResponse[0];wordCount != 0{
		byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
		if n != int(byteCount) + 45 {
			fmt.Println("[-]", info.HostName + ":445", "ms17010 invalid session setup AndX response")
		}else{
			for i:= 0;i<len(sessionSetupResponse)-1;i++{
				if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 && i > 10 {
					os = string(sessionSetupResponse[10:i])
					os = strings.Replace(os, string([]byte{0x00}), "", -1)
					break
				}
			}
		}
	}
	userID := reply[32:34]
	treeConnectRequest[32] = userID[0]
	treeConnectRequest[33] = userID[1]
	// TODO change the ip in tree path though it doesn't matter
	_, err = conn.Write(treeConnectRequest)
	if err != nil {
		return err
	}
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return err
	}

	treeID := reply[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]

	_, err = conn.Write(transNamedPipeRequest)
	if err != nil {
		return err
	}
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return err
	}
	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {

		result := fmt.Sprintf("[+] %s\tMS17-010\t(%s)", info.HostName, os)
		fmt.Println(result)
		// detect present of DOUBLEPULSAR SMB implant
		trans2SessionSetupRequest[28] = treeID[0]
		trans2SessionSetupRequest[29] = treeID[1]
		trans2SessionSetupRequest[32] = userID[0]
		trans2SessionSetupRequest[33] = userID[1]

		_, err = conn.Write(trans2SessionSetupRequest)
		if err != nil {
			return err
		}
		if n, err := conn.Read(reply); err != nil || n < 36 {
			return err
		}

		if reply[34] == 0x51 {
			result := fmt.Sprintf("[+] %s [DOUBLEPULSAR SMB IMPLANT]", info.HostName)
			fmt.Println(result)
		}
	} else {
		result := fmt.Sprintf("[+] %s(%s)", info.HostName, os)
		fmt.Println(result)
	}
	return nil
}
func MS17070(info *config.HostData)error{
	err := ms17070Scan(info)
	if err != nil {
		return err
	}
	return nil
}