package config

import (
	"fmt"
	"os"
)

// 初始化日志文件

func WriteLogFile(filename string,str string,inlog bool){
	if inlog == true{
		fmt.Println(str)
		var text = []byte(str + "\n")
		file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0777)
		if err != nil {
			fmt.Printf("Create Log File %s is err: %s\n",filename,err.Error())
		}
		_,err = file.Write(text)
		if err != nil {
			fmt.Printf("Write Log File %s is err: %s\n",filename,err.Error())
		}
	}else{
		fmt.Println(str)
	}

}