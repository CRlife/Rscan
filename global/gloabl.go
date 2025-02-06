package global

import (
	"os"
	"sync"
)

// 公共变量
var (
	SuccessLog  = "log.log"  //运行记录
	PrintLock   sync.RWMutex //并发输出写入
	WebURl      = ""         //web扫描时临时后缀
	SaveIMG     = false      //web扫描时是否进行截图,本地需要有chrom浏览器
	SsaveIMGDIR = "WebScreenshot"
)

// AppendToFile 创建追加写入函数

// PathExists 文件是否存在
func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

// InSlice 判断字符串是否在 slice 中。
func InSlice(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

// RemoveDuplicates 切片去重
func RemoveDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var list []string

	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
