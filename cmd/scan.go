package cmd

import (
	"github.com/spf13/cobra"
	"rscan/scan"
)

var ScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "资产测绘、指纹识别、红队打点、漏洞扫描",
	Run:   scan.ParseFlags,
}

func init() {
	rootCmd.AddCommand(ScanCmd)
	ScanCmd.Flags().StringP("ip", "i", "", "此参数是扫描的IP地址,格式支持192.168.1.1,192.168.1.1/24,192.168.1-10")
	ScanCmd.Flags().StringP("ipfile", "", "", "此参数是扫描的IP文件,一行一个")
	ScanCmd.Flags().StringP("url", "u", "", "此参数是扫描单个URL地址")
	ScanCmd.Flags().StringP("urlfile", "", "", "此参数是扫描的URL文件,一行一个")
	ScanCmd.Flags().StringP("port", "p", "top500", "此参数是指定的端口，默认端口top500,可指定top100、top1000")
	ScanCmd.Flags().StringP("exclude", "e", "", "此参数排除扫描的端口,格式支持:1,2,3")
	ScanCmd.Flags().StringP("excludeip", "", "noip.txt", "此参数排除扫描的IP")
	ScanCmd.Flags().Bool("noping", false, "此参数是禁止ping检测")
	ScanCmd.Flags().IntP("chan", "c", 150, "并发数量")
	ScanCmd.Flags().IntP("time", "t", 5, "超时等待时常/s")
	ScanCmd.Flags().Bool("random", false, "打乱主机顺序")
	ScanCmd.Flags().Bool("img", false, "此参数进行保存WEB截图")
	ScanCmd.Flags().Bool("nocrack", false, "此参数是不进行弱口令扫描")
	ScanCmd.Flags().Bool("nopoc", false, "此参数是不进行poc漏洞扫描")
	ScanCmd.Flags().StringP("userfile", "", "", "此参数是自定义用户字典文件")
	ScanCmd.Flags().StringP("passwdfile", "", "", "此参数是自定义密码字典文件")
	ScanCmd.Flags().StringP("proxy", "x", "", "设置http代理,格式：http://127.0.0.1:8080")
}
