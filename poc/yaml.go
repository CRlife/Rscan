package poc

import (
	"embed"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/fs"
	"strings"
	"time"
)

//go:embed yaml-poc/*.yaml
var yamlFS embed.FS

type RuleMap []RuleItem

type RuleItem struct {
	Key   string
	Value []Rules
}

type Config struct {
	Name          string  `yaml:"name"`          //漏洞名称
	Description   string  `yaml:"description"`   //漏洞描述
	AlwaysExecute bool    `yaml:"alwaysExecute"` //是否直接执行不考虑app等组件
	MatchCount    int     `yaml:"matchCount"`    //匹配规则的数量
	Rules         []Rules `yaml:"rules"`
	Groups        RuleMap `yaml:"groups"`
}

type Rules struct {
	Method          string            `yaml:"method"`           //请求类型
	Path            string            `yaml:"path"`             //请求路径
	Headers         map[string]string `yaml:"headers"`          //请求头
	Body            string            `yaml:"body"`             //请求体
	Search          string            `yaml:"search"`           //匹配查询
	FollowRedirects bool              `yaml:"follow_redirects"` //是否重定向
	Expression      Expression        `yaml:"expression"`       //返回值
	Continue        bool              `yaml:"continue"`
	Timeout         time.Duration     `yaml:"timeout"` //等待时常
	Dnslog          string            `yaml:"dnslog"`  //是否进行dnslog探测
}

type Expression struct {
	Status      int               `yaml:"status"`      //返回的状态码
	Headers     map[string]string `yaml:"headers"`     //返回头
	BodyALL     []string          `yaml:"body_all"`    //必须包含所有特征
	BodyAny     []string          `yaml:"body_any"`    //包含任意特征
	Time        float64           `yaml:"sleep"`       //总共耗时
	DnslogCheck bool              `yaml:"dnslogCheck"` //dnslog成功状态
}

// parseConfigs 解析yaml文件
func parseConfigs(dir string) ([]Config, error) {
	var configs []Config

	dirEntries, err := fs.ReadDir(yamlFS, dir)
	if err != nil {
		fmt.Println("这是第一个错误")
		fmt.Println(err)

		return nil, err
	}

	for _, entry := range dirEntries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".yaml") {
			data, err := fs.ReadFile(yamlFS, dir+"/"+entry.Name())
			if err != nil {

				return nil, err
			}

			var config Config
			err = yaml.Unmarshal(data, &config)
			if err != nil {

				return nil, err
			}

			configs = append(configs, config)
		}
	}

	return configs, nil
}
