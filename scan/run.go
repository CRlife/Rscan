package scan

import (
	"github.com/spf13/cobra"
	"rscan/global"
	"rscan/scan/crack"
	"rscan/scan/proxy"
	"sync"
)

type ProxyConfig interface {
	GetProxy() string // 获取代理的方法
}

type Config struct {
	Proxy string
}

func (c *Config) GetProxy() string {
	return c.Proxy
}

var (
	port       string //接受cli要扫描的端口
	iplist     []string
	portlist   []string
	urllist    []string
	NoPing     bool                      //是否禁止ping监测
	Carck      bool                      //是否进行弱口令扫描
	Poc        bool                      //是否进行poc扫描
	ch         = make(chan struct{}, 30) //控制并发数
	wg         = sync.WaitGroup{}
	chancount  int    //并发数量
	Timeout    int    //超时等待时常
	random     bool   //打乱顺序
	infolist   []INFO //成功的主机列表
	allcount   uint32 //IP*PORT的总数量
	donecount  uint32 //线程技术的数量
	outputMux  sync.Mutex
	userfile   string //user字典路径
	passwdfile string //passwd字典路径
	Proxy      string //代理地址

)

type INFO struct {
	Host     string //主机
	Port     string //开放端口
	Protocol string //协议
}

func ParseFlags(cmd *cobra.Command, args []string) {
	ipFile, _ := cmd.Flags().GetString("ipfile") //读取ip文件
	parseFileIP(ipFile)

	urlFile, _ := cmd.Flags().GetString("urlfile") //读取url文件
	if urlFile != "" {
		parseFileURL(urlFile)
	}

	ur, _ := cmd.Flags().GetString("url")

	if ur != "" {
		urllist = append(urllist, ur)
	}

	ip, _ := cmd.Flags().GetString("ip")

	if ip != "" {
		parseIP(ip)
	}

	excludeiplist, _ := cmd.Flags().GetString("excludeip") //去重IP以及排查过滤IP
	removeIP(excludeiplist)

	port, _ = cmd.Flags().GetString("port")
	parsePort(port)

	excludeport, _ := cmd.Flags().GetString("exclude") //去重端口以及排查过滤端口
	excludePort(excludeport)

	NoPing, _ = cmd.Flags().GetBool("noping")

	chancount, _ = cmd.Flags().GetInt("chan") //并发数量
	ch = make(chan struct{}, chancount)

	Timeout, _ = cmd.Flags().GetInt("time") //超时等待时常

	Proxy, _ = cmd.Flags().GetString("proxy") //设置代理
	proxy.SetProxy(Proxy)

	nocrack, _ := cmd.Flags().GetBool("nocrack") //弱口令扫描
	Carck = !nocrack

	nopoc, _ := cmd.Flags().GetBool("nopoc") //poc扫描
	Poc = !nopoc

	random, _ = cmd.Flags().GetBool("random") //打乱顺序

	imgsave, _ := cmd.Flags().GetBool("img") //保存网页截图
	global.SaveIMG = imgsave

	userfile, _ = cmd.Flags().GetString("userfile")
	passwdfile, _ = cmd.Flags().GetString("passwdfile")
	crack.Checkdistfile(userfile, passwdfile) //先读取是否有自定义的字典文件

	if ur != "" || urlFile != "" {
		URLscan(urllist)
	}

	if ip != "" || ipFile != "" {
		scanPort()
	}

}
