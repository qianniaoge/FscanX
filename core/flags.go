package core

import (
	"FscanX/config"
	"errors"
	"fmt"
	"github.com/urfave/cli/v2"
	"os"
	"reflect"
	"regexp"
)

func GetFlag(){
	var enter config.EnterFlag
	var reg = regexp.MustCompile("((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}")
	var app = cli.App{
		Commands: []*cli.Command{
			{
				Name: "extend",
				Usage: "Use some external toolsets",
				Subcommands: []*cli.Command{
					{
						Name:"mssql",
						Usage: "mssql external toolset",
						Flags: []cli.Flag{
							&cli.StringFlag{
							 	Name: "username",
							 	Value: "sa",
							 	Usage: "mssql connects to the user name",
							},
							&cli.StringFlag{
								Name:"password",
								Usage: "mssql connect to the user password",
							},
							&cli.StringFlag{
								Name:"hostname",
								Usage: "mssql connects to the remote address",
							},
							&cli.IntFlag{
								Name: "port",
								Value: 1433,
								Usage: "mssql connects to the remote address port",
							},
							&cli.BoolFlag{
								Name:"shell",
								Value: false,
								Usage: "mssql enables command-line mode",
							},
							&cli.StringFlag{
								Name: "cmd",
								Usage: "execute the command through mssql",
							},
							&cli.IntFlag{
								Name: "method",
								Value: 1,
								Usage: "Execute method" +
									"\n xp_cmdshell   1   <*>Echoable<*>" +
									"\n sp_oacreate   2   <*>Echoable<*>"+
									"\n open_CLR      3   <*>No Echoable<*>" +
									"\n close_CLR     4   <*>No Echoable<*>",
							},
							&cli.BoolFlag{
								Name: "log",
								Value: false,
								Usage: "Whether to output to log files",
							},
						},
						Action: func(c *cli.Context) error {
							if reflect.ValueOf(c.Value("hostname")).String() == ""{
								return errors.New("[-] mssql connection remote address cannot be empty")
							}
							if reflect.ValueOf(c.Value("password")).String() == ""{
								return errors.New("[-] mssql may be need a passowd")
							}
							config.MSSQLFLAG.Host = reflect.ValueOf(c.Value("hostname")).String()
							config.MSSQLFLAG.Port = int(reflect.ValueOf(c.Value("port")).Int())
							config.MSSQLFLAG.PassWord = reflect.ValueOf(c.Value("password")).String()
							config.MSSQLFLAG.UserName = reflect.ValueOf(c.Value("username")).String()
							config.MSSQLFLAG.Method = reflect.ValueOf(c.Value("method")).Int()
							config.MSSQLFLAG.Commandline = reflect.ValueOf(c.Value("shell")).Bool()
							config.MSSQLFLAG.Command = reflect.ValueOf(c.Value("cmd")).String()
							config.Inlog = reflect.ValueOf(c.Value("log")).Bool()
							enter.ScanTypeMain = "mssql-extend"
							return nil
						},
					},
					{
						Name: "redis",
						Usage: "redis external toolset",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:"rf",
								Usage: "redis file to write sshkey file (as --rf id_rsa.pub)",
							},
							&cli.StringFlag{
								Name: "rs",
								Usage: "redis shell to write cron file (as: --rs 192.168.1.1:6666)",
							},
							&cli.StringFlag{
								Name: "hostname",
								Usage: "redis connects to the remote address",
							},
							&cli.IntFlag{
								Name: "port",
								Value: 6379,
								Usage: "The list of ports to be scanned",
							},
							&cli.StringFlag{
								Name: "password",
								Usage: "redis connect password",
							},
							&cli.BoolFlag{
								Name: "log",
								Value: false,
								Usage: "Whether to output to log files",
							},
						},
						Action: func(c *cli.Context) error {
							if reflect.ValueOf(c.Value("hostname")).String() == ""{
								return errors.New("[-] redis connection remote address cannot be empty")
							}
							if reflect.ValueOf(c.Value("rs")).String() == "" && reflect.ValueOf(c.Value("rf")).String() == ""{
								return errors.New("[-] redis may be need a sshkey file or shell command")
							}
							config.REDISFLAG.Host = reflect.ValueOf(c.Value("hostname")).String()
							config.REDISFLAG.Port = int(reflect.ValueOf(c.Value("port")).Int())
							config.REDISFLAG.PassWord = reflect.ValueOf(c.Value("password")).String()
							config.RedisFile = reflect.ValueOf(c.Value("rf")).String()
							config.RedisShell = reflect.ValueOf(c.Value("rs")).String()
							config.Inlog = reflect.ValueOf(c.Value("log")).Bool()
							enter.ScanTypeMain = "redis-extend"
							return nil
						},
					},
					{
						Name: "ssh",
						Usage: "ssh external toolset",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name: "cmd",
								Usage: "execute shell command when connect ssh",
							},
							&cli.StringFlag{
								Name: "sk",
								Usage: "Use ssh key certification (as --sk id_rsa)",
							},
							&cli.StringFlag{
								Name: "hostname",
								Usage: "redis connects to the remote address",
							},
							&cli.IntFlag{
								Name: "port",
								Value: 22,
								Usage: "The list of ports to be scanned",
							},
							&cli.StringFlag{
								Name: "username",
								Value: "root",
								Usage: "ssh connects to the user name",
							},
							&cli.StringFlag{
								Name: "password",
								Usage: "ssh connects to the user name",
							},
							&cli.BoolFlag{
								Name: "log",
								Value: false,
								Usage: "Whether to output to log files",
							},
						},
						Action: func(c *cli.Context) error {
							if reflect.ValueOf(c.Value("hostname")).String() == ""{
								return errors.New("[-] ssh connection remote address cannot be empty")
							}
							if reflect.ValueOf(c.Value("sk")).String() == "" && reflect.ValueOf(c.Value("cmd")).String() == ""{
								return errors.New("[-] ssh may be need a sshkey file or rs command")
							}
							if reflect.ValueOf(c.Value("sk")).String() == ""&& (reflect.ValueOf(c.Value("password")).String() == "" || reflect.ValueOf(c.Value("username")).String() == ""){
								return errors.New("[-] mssql may be need a username and password")
							}
							config.SSHFLAG.Host = reflect.ValueOf(c.Value("hostname")).String()
							config.SSHFLAG.Port = int(reflect.ValueOf(c.Value("port")).Int())
							config.SSHFLAG.Command = reflect.ValueOf(c.Value("cmd")).String()
							config.SSHFLAG.SshKey = reflect.ValueOf(c.Value("sk")).String()
							config.SSHFLAG.UserName = reflect.ValueOf(c.Value("username")).String()
							config.SSHFLAG.PassWord = reflect.ValueOf(c.Value("password")).String()
							config.Inlog = reflect.ValueOf(c.Value("log")).Bool()
							enter.ScanTypeMain = "ssh-extend"
							return nil
						},
					},
				},
			},
			{
				Name:"hostscan",
				Usage: "Discover surviving hosts in different ways",
				Subcommands:  []*cli.Command{
					{
						Name: "netbios",
						Usage: "Using NetBIOS protocol to discover hosts",
						Flags: []cli.Flag{
							&cli.IntFlag{
								Name: "thread",
								Value: 1000,
								Usage: "set gorouite for fscanX",
							},
							&cli.BoolFlag{
								Name: "log",
								Value: false,
								Usage: "Whether to output to log files",
							},
						},
						Action: func(c *cli.Context) error {
							enter.Thread = reflect.ValueOf(c.Value("thread")).Int()
							if reg.MatchString(c.Args().Get(0)) == true{
								enter.ScanHost = c.Args().Get(0)
							}else{
								return errors.New("FscanX need a scan host address")
							}
							config.Inlog = reflect.ValueOf(c.Value("log")).Bool()
							enter.ScanTypeMain = "hostscan-netbios"
							return nil
					},
				},
				{
						Name: "icmp",
						Usage: "Icmp or ping is used for scanning",
						Flags: []cli.Flag{
							&cli.IntFlag{
								Name: "thread",
								Value: 1000,
								Usage: "set gorouite for fscanX",
							},
							&cli.BoolFlag{
								Name: "noping",
								Value: false,
								Usage: "The ping command is not used",
							},
							&cli.BoolFlag{
								Name: "log",
								Value: false,
								Usage: "Whether to output to log files",
							},
						},
						Action: func(c *cli.Context) error {
							enter.Thread = reflect.ValueOf(c.Value("thread")).Int()
							if reg.MatchString(c.Args().Get(0)) == true{
								enter.ScanHost = c.Args().Get(0)
							}else{
								return errors.New("FscanX need a scan host address")
							}
							enter.Noping = reflect.ValueOf(c.Value("noping")).Bool()
							config.Inlog = reflect.ValueOf(c.Value("log")).Bool()
							enter.ScanTypeMain = "hostscan-icmp"
							return nil
						},
					},
					{
						Name: "smart",
						Usage: "Use multiple protocols to scan for live hosts",
						Flags: []cli.Flag{
							&cli.IntFlag{
								Name: "thread",
								Value: 1000,
								Usage: "set gorouite for fscanX",
							},
							&cli.BoolFlag{
								Name: "log",
								Value: false,
								Usage: "Whether to output to log files",
							},
						},
						Action: func(c *cli.Context) error {
							enter.Thread = reflect.ValueOf(c.Value("thread")).Int()
							if reg.MatchString(c.Args().Get(0)) == true{
								enter.ScanHost = c.Args().Get(0)
							}else{
								return errors.New("FscanX need a scan host address")
							}
							config.Inlog = reflect.ValueOf(c.Value("log")).Bool()
							enter.ScanTypeMain = "hostscan-smart"
							return nil
						},
					},
					{
						Name: "oxid",
						Usage: "Scan 135 to obtain nic information and return the scan result",
						Flags: []cli.Flag{
							&cli.IntFlag{
								Name: "thread",
								Value: 1000,
								Usage: "set gorouite for fscanX",
							},
							&cli.BoolFlag{
								Name: "log",
								Value: false,
								Usage: "Whether to output to log files",
							},
						},
						Action: func(c *cli.Context) error {
							enter.Thread = reflect.ValueOf(c.Value("thread")).Int()
							if reg.MatchString(c.Args().Get(0)) == true{
								enter.ScanHost = c.Args().Get(0)
							}else{
								return errors.New("FscanX need a scan host address")
							}
							config.Inlog = reflect.ValueOf(c.Value("log")).Bool()
							enter.ScanTypeMain = "hostscan-oxid"
							return nil
						},
					},
				},
			},
			{
				Name: "portscan",
				Usage: "TCP is used to scan ports and fragile services are scanned by the Fragile parameter",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: "fragile",
						Value: "all",
						Usage: "Detection and blasting of vulnerable ports\n"+
							"\tYou can specify services mssql, mysql, redis, ftp, ssh, mongodb, postgre\n" +
							"\tUse (,) to separate multiple services (--fragile mssql,mysql,ssh)\n"+
							"\tIf you do not scan for port service vulnerabilities, enter nil(--fragile nil)",
					},
					&cli.StringFlag{
						Name: "port",
						Usage: "The list of ports to be scanned",
					},
					&cli.IntFlag{
						Name: "thread",
						Value: 1000,
						Usage: "set gorouite for fscanX",
					},
					&cli.BoolFlag{
						Name: "log",
						Value: false,
						Usage: "Whether to output to log files",
					},
				},
				Action: func(c *cli.Context) error {
					if reg.MatchString(c.Args().Get(0)) == true{ // 获取扫描的IP地址列表
						enter.ScanHost = c.Args().Get(0)
					}else{
						return errors.New("FscanX need a scan host address")
					}
					enter.Fragile = reflect.ValueOf(c.Value("fragile")).String()
					enter.Thread = reflect.ValueOf(c.Value("thread")).Int()
					enter.Ports = reflect.ValueOf(c.Value("port")).String()
					config.Inlog = reflect.ValueOf(c.Value("log")).Bool()
					enter.ScanTypeMain = "portscan"
					return nil
				},
			},
			{
				Name: "vulscan",
				Usage: "intranet host vulnerability scanning",
				Subcommands: []*cli.Command{
					{
						Name: "ms17010",
						Usage: "Eternal Blue vulnerability scan",
						Flags: []cli.Flag{
							&cli.IntFlag{
								Name: "thread",
								Value: 1000,
								Usage: "set gorouite for fscanX",
							},
							&cli.BoolFlag{
								Name: "log",
								Value: false,
								Usage: "Whether to output to log files",
							},
						},
						Action: func(c *cli.Context) error {
							if reg.MatchString(c.Args().Get(0)) == true {
								enter.ScanHost = c.Args().Get(0)
							}else{
								return errors.New("FscanX need a scan host address")
							}
							enter.Thread = reflect.ValueOf(c.Value("thread")).Int()
							config.Inlog = reflect.ValueOf(c.Value("log")).Bool()
							enter.ScanTypeMain = "vulscan-ms17010"
							return nil
						},
					},
					{
						Name: "smbghost",
						Usage: "Eternal Black vulnerability scan (smbghost)",
						Flags: []cli.Flag{
							&cli.IntFlag{
								Name: "thread",
								Value: 1000,
								Usage: "set gorouite for fscanX",
							},
							&cli.BoolFlag{
								Name: "log",
								Value: false,
								Usage: "Whether to output to log files",
							},
						},
						Action: func(c *cli.Context) error {
							if reg.MatchString(c.Args().Get(0)) == true {
								enter.ScanHost = c.Args().Get(0)
							}
							enter.Thread = reflect.ValueOf(c.Value("thread")).Int()
							config.Inlog = reflect.ValueOf(c.Value("log")).Bool()
							enter.ScanTypeMain = "vulscan-smbghost"
							return nil
						},
					},
				},
			},
			{
				Name:"webscan",
				Usage: "discovery and vulnerability scanning of the web server",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name: "thread",
						Value: 1000,
						Usage: "set gorouite for fscanX",
					},
					&cli.StringFlag{
						Name: "cookie",
						Usage: "set cookies to use when scanning",
					},
					&cli.StringFlag{
						Name: "proxy",
						Usage: "set http proxy to use when scanning",
					},
					&cli.StringFlag{
						Name: "port",
						Usage: "The list of ports to be scanned",
					},
					&cli.BoolFlag{
						Name: "fragile",
						Value: false,
						Usage: "Detection and blasting of vulnerable web",
					},
					&cli.BoolFlag{
						Name: "log",
						Value: false,
						Usage: "Whether to output to log files",
					},
				},
				Action: func(c *cli.Context) error {
					enter.Thread = reflect.ValueOf(c.Value("thread")).Int()
					if reg.MatchString(c.Args().Get(0)) == true{
						enter.ScanHost = c.Args().Get(0)
					}else{
						return errors.New("FscanX need a scan host address")
					}
					if reflect.ValueOf(c.Value("cookie")).String() != ""{
						config.WebConfig.SetCookie = reflect.ValueOf(c.Value("cookie")).String()
					}
					if reflect.ValueOf(c.Value("proxy")).String() != ""{
						config.WebConfig.SetProxy = reflect.ValueOf(c.Value("proxy")).String()
					}
					if reflect.ValueOf(c.Value("port")).String() != ""{
						enter.Ports = reflect.ValueOf(c.Value("port")).String()
					}
					enter.FragileBool = reflect.ValueOf(c.Value("fragile")).Bool()
					config.Inlog = reflect.ValueOf(c.Value("log")).Bool()
					enter.ScanTypeMain = "webscan"
					return nil
				},
			},
		},
	}
	err := app.Run(os.Args)
	if err == nil {
		Scanner(enter)
	}else{
		config.WriteLogFile(config.LogFile,err.Error(),config.Inlog)
		fmt.Println(app.VisibleFlags())
	}
}