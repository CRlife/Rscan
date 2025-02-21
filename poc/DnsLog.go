package poc

import (
	"bytes"
	"fmt"
	"gopkg.in/yaml.v2"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Dnslog struct {
	CeyeApi    string `yaml:"ceyeApi"`
	CeyeDomain string `yaml:"ceyeDomain"`
	FofaEmail  string `yaml:"fofaEmail"`
	FofaKey    string `yaml:"fofaKey"`
	FofaSize   int    `yaml:"fofaSize"`
}

var (
	ceyeApi    string
	ceyeDomain string
)

func init() {
	// 检查配置文件是否存在，如果不存在则创建
	if _, err := os.Stat("config.yaml"); os.IsNotExist(err) {
		createConfigFile()
	}

	// 读取配置文件
	config, err := readConfigFile()
	if err != nil {
		fmt.Printf("读取配置文件失败: %v\n", err)
		os.Exit(1)
	}

	ceyeApi = config.CeyeApi
	ceyeDomain = config.CeyeDomain
}

func createConfigFile() {
	config1 := Dnslog{
		CeyeApi:    "", // 默认值为空
		CeyeDomain: "", // 默认值为空
		FofaEmail:  "",
		FofaKey:    "",
		FofaSize:   100,
	}

	data, err := yaml.Marshal(&config1)
	if err != nil {
		fmt.Printf("创建配置文件失败: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile("config.yaml", data, 0644)
	if err != nil {
		fmt.Printf("写入配置文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("配置文件config.yaml已创建")
	os.Exit(0)
}

func readConfigFile() (*Dnslog, error) {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		return nil, err
	}

	config := &Dnslog{}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func dnsLog() map[string]string {

	letters := "1234567890abcdefghijklmnopqrstuvwxyz"
	randSource := rand.New(rand.NewSource(time.Now().UnixNano()))
	sub := RandomStr(randSource, letters, 8)

	// 修复 urlStr 的格式
	urlStr := fmt.Sprintf("http://%s.%s", sub, ceyeDomain)

	// 解析 URL
	u, err := url.Parse(urlStr)
	if err != nil {
		// 如果解析失败，返回错误信息
		return map[string]string{
			"error": fmt.Sprintf("DNSLog不可用: %v\n", err),
		}
	}

	// 构造返回的 map
	result := map[string]string{
		"url":    urlStr,
		"domain": u.Hostname(),
		"ip":     u.Host,
	}
	return result
}

func DnsLogCheck(r string, timeout int64) bool {

	client := &http.Client{}

	time.Sleep(time.Second * time.Duration(timeout))
	sub := strings.Split(r, ".")[0]
	urlStr := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s", ceyeApi, sub)
	req, _ := http.NewRequest("GET", urlStr, nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("DNSLog不可用\n")
		return false
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	if !bytes.Contains(respBody, []byte(`"data": []`)) && bytes.Contains(respBody, []byte(`"message": "OK"`)) { // api返回结果不为空
		return true
	}
	return false
}
