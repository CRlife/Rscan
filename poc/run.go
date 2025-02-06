package poc

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"rscan/global"
	"strings"
	"sync"
	"time"
)

var ListPocInfo []Flagcve

type Flagcve struct {
	Url  string
	Cve  string
	Flag string
}

func CheckPoc(url, app string) {
	wg := sync.WaitGroup{}

	if strings.HasSuffix(url, "/") {
		url = url[:len(url)-1]
	}

	app = strings.ToLower(app)

	dirPocs, err := parseConfigs("yaml-poc")
	if err != nil {
		return
	}

	// 这是运行yaml格式的漏洞
	for _, poc := range dirPocs {
		apps := strings.Split(app, ",") // 分割app
		for _, singleApp := range apps {
			if strings.Contains(strings.ToLower(poc.Name), singleApp) && singleApp != "" {
				wg.Add(1)
				go executeRequest(url, poc, &wg)
			}
		}

		if poc.AlwaysExecute {
			wg.Add(1)
			go executeRequest(url, poc, &wg)
		}
	}

	// 这是特定的poc漏洞
	if strings.Contains(app, "spring") {
		CVE_2022_22947(url, "pwd")
	}
	//执行CVE_2024_23897
	if strings.Contains(app, "jenkins") {
		CVE_2024_23897(url)
	}
	//执行CVE_2024_23897
	if strings.Contains(app, "zabbix-监控系统") {
		CVE_2022_23131(url)
	}
	//checkShiroCookie
	if strings.Contains(app, "shiro框架") {
		checkShiroCookie(url)
	}

	// 这是未授权的漏洞
	authPocs := map[string]Flagcve{
		"elasticsearch[未授权访问]": {url, "elasticsearch未授权访问", "可通过/_cat/indices?v获取所有索引信息"},
		"couchdb":              {url, "CouchDB未授权访问", "可通过/_all_dbs获取所有数据库"},
		"hadoop":               {url, "Hadoop-Administration未授权访问", ""},
		"apache-spark":         {url, "Apache-Spark未授权访问", ""},
		"kafka-manager":        {url, "Kafka-Manager未授权访问", ""},
		"jenkins[未授权访问]":       {url, "jenkins未授权访问", ""},
	}
	for aps, flag := range authPocs {
		if strings.Contains(app, aps) {
			echoFlag(flag)
		}
	}
	wg.Wait()

}

// 基于yaml格式处理http请求
func executeRequest(URL string, config Config, wg *sync.WaitGroup) {
	defer wg.Done()

	Count := 0 // 用于记录匹配规则的数量
	variableMap := make(map[string]interface{})
	defer func() { variableMap = nil }()

	for _, rule := range config.Rules {

		foundMissingHeader := true
		var domain string
		var ok bool
		var err error
		rule.Body, err = decodeBase64IfNeeded(rule.Body)
		if err != nil {
			fmt.Println("Base64解码错误:", err)
			continue
		}

		if rule.Dnslog != "" {
			result := dnsLog()
			domain, ok = result["domain"]
			if ok && domain != "" {
				for k, v := range result {
					variableMap[k] = v
				}
			}
		}

		for k1, v1 := range variableMap {
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range rule.Headers {
				if !strings.Contains(v2, "{{"+k1+"}}") {
					continue
				}
				rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
			rule.Path = strings.ReplaceAll(rule.Path, "{{"+k1+"}}", value)
			rule.Body = strings.ReplaceAll(rule.Body, "{{"+k1+"}}", value)
		}

		path := replacepath(rule.Path) //path中可能有变量进行替换
		baseurl := fmt.Sprintf("%s%s", URL, path)

		values, err := url.ParseQuery(rule.Body) //解析body字符串为URL编码
		var req *http.Request

		if strings.Contains(rule.Headers["Content-Type"], "application") ||
			strings.Contains(rule.Headers["Content-Type"], "text/") ||
			strings.Contains(rule.Headers["Content-Type"], "multipart/form-data") {
			req, err = http.NewRequest(rule.Method, baseurl, strings.NewReader(rule.Body)) //json不需要编码

		} else {
			req, err = http.NewRequest(rule.Method, baseurl, strings.NewReader(values.Encode()))

		}
		if err != nil {
			continue
		}

		for k, v := range rule.Headers { //设置header
			req.Header.Set(k, v)
		}

		resp, elapsedtime, err := NewRequest(req, rule.Timeout, rule.FollowRedirects)
		if err != nil {
			continue
		}

		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(resp.Body)

		if rule.Search != "" {
			result := doSearch(rule.Search, GetHeader(resp.Header)+string(bodyBytes))
			if len(result) > 0 { // 正则匹配成功
				for k, v := range result {
					variableMap[k] = v
				}
			}
		}

		if resp.StatusCode != rule.Expression.Status && rule.Expression.Status != 0 { //状态码判断
			//fmt.Println(errors.New(fmt.Sprintf("当前请求状态码为:%d,与yaml中%d不符!", resp.StatusCode, rule.Expression.Status)))
			continue
		}

		if rule.Expression.DnslogCheck {
			if !DnsLogCheck(domain, 3) {
				//fmt.Println(errors.New(fmt.Sprintf("DNSlog请求失败")))
				continue
			}
		}

		for key, expectedValue := range rule.Expression.Headers {
			actualValue := resp.Header.Get(key) // 获取实际的头部值
			if actualValue == "" {
				//fmt.Printf("响应中缺少头部 %s\n", key)
				foundMissingHeader = false

			} else if !strings.Contains(actualValue, expectedValue) {
				//fmt.Printf("响应头 %s 的值不包含期望值 (实际: %s, 期望包含: %s)\n", key, actualValue, expectedValue) // 如果不包含，输出相关信息
				foundMissingHeader = false
			}
		}
		if !foundMissingHeader {
			continue
		}

		strBody := string(bodyBytes)

		if len(rule.Expression.BodyALL) >= 1 {
			if !allSubstringsPresent(strBody, rule.Expression.BodyALL) {
				//fmt.Println(errors.New("返回body中不包含规定的任意数据！"))
				continue
			}
		}

		if len(rule.Expression.BodyAny) >= 1 {
			if !anySubstringsPresent(strBody, rule.Expression.BodyAny) {
				//fmt.Println(errors.New("返回body中不包含规定的所有数据！"))
				continue
			}
		}

		if rule.Expression.Time > 0 {
			if elapsedtime < rule.Expression.Time { //实际请求如果小于规定的时间则不存在延迟注入
				//fmt.Println(elapsedtime)
				continue
			}
		}

		Count++

		if Count >= config.MatchCount {
			if os.Getenv("poc") == "on" {
				fmt.Println(strBody, "\n---------------------")
			}
			flags := Flagcve{baseurl, config.Name, config.Description}
			echoFlag(flags)
		}
	}
}

func doSearch(re string, body string) map[string]string {
	r, err := regexp.Compile(re)
	if err != nil {
		fmt.Println("[-] regexp.Compile error: ", err)
		return nil
	}
	result := r.FindStringSubmatch(body)
	names := r.SubexpNames()
	if len(result) > 1 && len(names) > 1 {
		paramsMap := make(map[string]string)
		for i, name := range names {
			if i > 0 && i <= len(result) {
				if strings.HasPrefix(re, "Set-Cookie:") && strings.Contains(name, "cookie") {
					paramsMap[name] = optimizeCookies(result[i])
				} else {
					paramsMap[name] = result[i]
				}
			}
		}
		return paramsMap
	}
	return nil
}

func optimizeCookies(rawCookie string) (output string) {
	// Parse the cookies
	parsedCookie := strings.Split(rawCookie, "; ")
	for _, c := range parsedCookie {
		nameVal := strings.Split(c, "=")
		if len(nameVal) >= 2 {
			switch strings.ToLower(nameVal[0]) {
			case "expires", "max-age", "path", "domain", "version", "comment", "secure", "samesite", "httponly":
				continue
			}
			output += fmt.Sprintf("%s=%s; ", nameVal[0], strings.Join(nameVal[1:], "="))
		}
	}

	return
}

func GetHeader(header http.Header) (output string) {
	for name, values := range header {
		line := fmt.Sprintf("%s: %s\n", name, values)
		output = output + line
	}
	output = output + "\r\n"
	return
}

// replacepath 替换路径中的变量
func replacepath(path string) string {
	nowday := time.Now().Format("06_01_02") //当前日期23_08_22
	path = strings.ReplaceAll(path, "{01_01_01}", nowday)
	return path
}

// allSubstringsPresent 返回值是否同时包含
func allSubstringsPresent(str string, substrings []string) bool {
	for _, substring := range substrings {
		if !strings.Contains(str, substring) {
			return false
		}
	}
	return true
}

// anySubstringsPresent 返回值是否任意包含
func anySubstringsPresent(str string, substrings []string) bool {
	for _, substring := range substrings {
		if strings.Contains(str, substring) {
			return true
		}
	}
	return false
}

func echoFlag(flag Flagcve) {
	global.PrintLock.Lock()
	defer global.PrintLock.Unlock()
	ListPocInfo = append(ListPocInfo, Flagcve{flag.Url, flag.Cve, flag.Flag})
	global.LogToFile(global.LevelInfo, fmt.Sprintf("%s漏洞名称: %s漏洞描述: %s", flag.Url, flag.Cve, flag.Flag))

}

func decodeBase64IfNeeded(body string) (string, error) {
	// 正则表达式匹配 "Base64Decode" 后跟 Base64 编码的数据
	re := regexp.MustCompile(`Base64Decode\{([a-zA-Z0-9+/=]+)\}`)
	matches := re.FindStringSubmatch(body)

	if len(matches) > 1 {
		// 提取 Base64 编码的数据
		b64Data := matches[1]
		// Base64 解码
		bodyBytes, err := base64.StdEncoding.DecodeString(b64Data)
		if err != nil {
			return body, err
		}
		// 替换原始字符串中的 Base64 编码部分为解码后的字符串
		return re.ReplaceAllString(body, string(bodyBytes)), nil
	}
	// 如果没有找到Base64编码数据，直接返回原字符串
	return body, nil
}
