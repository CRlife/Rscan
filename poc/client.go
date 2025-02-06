package poc

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"rscan/scan/proxy"
	"time"
)

func NewRequest(req *http.Request, timeout time.Duration, redirect bool) (*http.Response, float64, error) {

	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	Proxy := proxy.GetProxy()
	if Proxy != "" {
		proxyURL, err := url.Parse(Proxy)
		if err != nil {
			return nil, 0, err // 返回错误
		}
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			Proxy: http.ProxyURL(proxyURL),
		}
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36")

	if timeout == 0 {
		timeout = 3 * time.Second
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if redirect {
				// 跟随重定向
				return nil
			} else {
				// 不跟随重定向
				return http.ErrUseLastResponse
			}
		},
	}

	start := time.Now() // 记录开始时间
	resp, err := client.Do(req)
	elapsed := time.Since(start) // 计算耗时
	return resp, elapsed.Seconds(), err

}
