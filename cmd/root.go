package cmd

import (
	"fmt"
	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"os"
	"rscan/global"
)

var rootCmd = &cobra.Command{
	Use:   "RScan",
	Short: "全自动扫描 一键支持-->弱口令爆破、漏洞扫描、端口扫描、指纹识别",
	Long:  `指纹规则600+|漏洞插件500+|存活探测、漏洞扫描、子域名扫描、端口扫描、各类服务数据库爆破、poc扫描、指纹识别->输出报告`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	myFigure := figure.NewColorFigure("RScan", "colossal", "cyan", true)
	myFigure.Print()

	fmt.Printf("Version: %s\nauthor : %s\n%s\n\n",
		color.GreenString("%s %s", global.Version, global.Releasenotes),
		color.MagentaString("%s", "CR"),
		color.RedString("%s", "免责声明:本软件仅用于经授权的渗透测试，禁止使用本工具实施未授权测试，若违法使用导致任何责任，与软件作者无关，均由用户自行承担。"),
	)
}
