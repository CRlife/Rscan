package scan

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/yaml.v2"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"rscan/global"
	"strconv"
	"strings"
)

// FoFoData Fofa结构体
type FoFoData struct {
	Err     bool       `json:"error"`
	Results [][]string `json:"results"`
}

type FOFA struct {
	FofaEmail string `yaml:"fofaEmail"`
	FofaKey   string `yaml:"fofaKey"`
	FofaSize  int    `yaml:"fofaSize"`
}

var (
	fofaEmail string
	fofaKey   string
	fofaSize  int
)

// parseIP解析IP地址范围 支持：192.168.1.1-100、192.168.1.1/24、192.168.1.1、baidu.com、http://www.baidu.com
func parseIP(ip string) {
	for _, p := range strings.Split(ip, ",") {
		replacer := strings.NewReplacer("https://", "", "http://", "")
		p = replacer.Replace(p)
		index := strings.Index(p, "/")
		// 如果存在后缀则写入环境变量，用于后续组件识别，漏洞扫描，否则进行首页扫描
		if strings.Index(p, "/") != -1 && index+1 < len(p) {
			url := p[index+1:]
			reMsk := regexp.MustCompile(`\b\d{1,2}`)
			if reMsk.FindString(url) == "" {
				global.WebURl = "/" + url
			}
		}

		//识别端口
		rePort := regexp.MustCompile(`:\d{1,5}`)
		matchPort := rePort.FindString(p)

		//1、匹配CIDR子网掩码的地址 2、匹配IP 3、匹配第一个/之前的数据
		reCIDR := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b`)
		reIP := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(-\d{1,3})?\b`)
		matchCIDR := reCIDR.FindString(p)
		if matchCIDR != "" {
			p = matchCIDR
		} else {
			matchIP := reIP.FindString(p)
			if matchIP != "" {
				p = matchIP
			} else {
				if index != -1 {
					p = p[:index]
				}
			}
		}
		//增加扫描端口
		p += matchPort

		checkPort := strings.Split(p, ":") //快速扫描
		if len(checkPort) == 2 {
			p = checkPort[0]
			portlist = []string{checkPort[1]}
		}

		switch {
		case strings.Contains(p, "-"):
			matched := reIP.MatchString(p)
			if !matched {
				continue
			}
			ipa := strings.Split(strings.Split(p, "-")[0], ".")

			start := strings.Split(ipa[3], "-")[0]
			startNum, _ := strconv.Atoi(start)

			end := strings.Split(p, "-")[1]
			endNum, _ := strconv.Atoi(end)

			ipa = ipa[:len(ipa)-1]
			ipStart := strings.Join(ipa, ".")

			if startNum > endNum {
				fmt.Printf("[-] 起始范围大于结束范围！\n")
				continue
			}

			for i := startNum; i <= endNum; i++ {
				nowIP := fmt.Sprintf("%s.%d", ipStart, i)
				iplist = append(iplist, nowIP)
			}

		case strings.Contains(p, "/"):
			_, ipnet, _ := net.ParseCIDR(p)
			for ipl := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ipl); incrementIP(ipl) {
				if len(ipl.To4()) == net.IPv4len {
					lastByte := ipl.To4()[3]
					if lastByte == 0 || lastByte == 255 {
					}
				}
				iplist = append(iplist, ipl.String())
			}

		default:
			if net.ParseIP(p) == nil {
				_, err := net.ResolveIPAddr("ip", p)
				if err != nil {
					fmt.Println(err)
					continue
				}
			}
			iplist = append(iplist, p)
		}
	}
}

// incrementIP 将ip地址增加1
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// parseFileIP解析扫描文件
func parseFileIP(path string) {
	if global.PathExists(path) {
		data, _ := os.ReadFile(path)
		for _, v := range strings.Split(string(data), "\n") {
			if v != "" {
				if strings.Contains(v, "-") {
					continue
				}
				replacer := strings.NewReplacer("\r", "", " ", "", "https://", "", "http://", "")
				v = replacer.Replace(v)
				if len(strings.Split(v, ":")) == 2 {
					ip := strings.Split(v, ":")[0]
					nowPort := strings.Split(v, ":")[1]
					portlist = append(portlist, nowPort)
					parseIP(ip)
					continue
				}
				parseIP(v)
			}
		}
	}
	return
}

// 读取fofa数据
func parseFoFa(cmd string) error {

	// 读取配置文件
	config, err := readConfigFile()
	if err != nil {
		fmt.Printf("读取配置文件失败: %v\n", err)
		os.Exit(1)
	}

	fofaEmail = config.FofaEmail
	fofaKey = config.FofaKey
	fofaSize = config.FofaSize

	if fofaEmail == "" || fofaKey == "" {
		return errors.New("配置文件fofaEmail或fofaKey为空")
	}
	fofaSizeint, err := strconv.Atoi(strconv.Itoa(fofaSize))
	if err != nil {
		fofaSizeint = 100
	}
	if fofaSizeint > 10000 {
		fofaSizeint = 10000
	} else if fofaSizeint == 0 {
		fofaSizeint = 100
	}

	url := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&page=1&size=%d&qbase64=%s", fofaEmail, fofaKey, fofaSizeint, base64.StdEncoding.EncodeToString([]byte(cmd)))
	res, err := http.Get(url)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(res.Body)
	resfofa := &FoFoData{}
	err = json.Unmarshal(body, resfofa)
	if err != nil {
		return err
	}
	if resfofa.Err {
		return errors.New("请求fofa失败")
	}
	if len(resfofa.Results) == 0 {
		return errors.New(fmt.Sprintf("[-] FOFA语句获取数据为空,调整一下吧！-》 %s", cmd))
	}
	portlist = []string{}
	for _, v := range resfofa.Results {
		iplist = append(iplist, v[1])
		portlist = append(portlist, v[2])
	}
	return nil
}

func readConfigFile() (*FOFA, error) {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		return nil, err
	}

	config := &FOFA{}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}
