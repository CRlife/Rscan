package proxy

var Proxy string // 全局代理变量

// SetProxy 设置全局代理
func SetProxy(proxy string) {
	Proxy = proxy
}

// GetProxy 获取全局代理
func GetProxy() string {
	return Proxy
}
