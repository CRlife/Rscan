package scan

import (
	"fmt"
	"net/url"
	"os"
	"rscan/global"
	"strings"
)

func parseFileURL(path string) {
	if !global.PathExists(path) {
		fmt.Printf("文件不存在\n")
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("文件读取失败: %v", err)
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if !strings.HasPrefix(strings.ToLower(line), "http://") &&
			!strings.HasPrefix(strings.ToLower(line), "https://") {
			continue
		}

		urllist = append(urllist, line)
	}
	//URLscan(urllist)
}

func URLscan(urllist []string) {
	defer func() {
		global.Percent(donecount, allcount) //输出100%的进度条
		echoPoc()                           //输出漏洞资产
		end()                               //输出总体结果
		saveXlsx(infolist, urllist)         //结果保存文件
	}()

	allcount = uint32(len(urllist))

	for _, URL := range urllist {
		ch <- struct{}{}
		wg.Add(1)
		u, err := url.Parse(URL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			fmt.Printf("无效 URL: %q\n", URL)
		}
		// 提取主机和端口
		host := u.Hostname()
		port := u.Port()

		// 如果端口未指定，则根据协议使用默认端口
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else if u.Scheme == "http" {
				port = "80"
			}
		}
		go IsPortOpen(host, port) //启动线程扫描端口是否存活

	}
	wg.Wait()

}
