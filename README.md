# 自动化漏扫工具、外网打点、内网扫描



## ✨ 1.5 版本核心升级

1. 新增通用漏洞扫描插件：备份文件扫描、Log4j 漏洞扫描、Fastjson 漏洞扫描
2. 强化服务识别：新增 NetBIOS 服务识别能力
3. 扩展爆破功能：支持 SNMP 服务爆破

![e589114e399c2bf9d4406d9fd42c750.png](https://github.com/CRlife/Rscan/blob/main/images/e589114e399c2bf9d4406d9fd42c750.png?raw=true)

![image-20251028173036243.png](https://github.com/CRlife/Rscan/blob/main/images/image-20251028173036243.png?raw=true)



## 🔍 核心功能

### 1. 超强指纹识别（600 + 指纹，2000 + 规则）

支持基于 hash、body、header 的全方位指纹识别，准确率超 95%，覆盖核心资产类型如下：

| 资产类别        | 支持范围                                                     |
| --------------- | ------------------------------------------------------------ |
| **OA 系统**     | 泛微、通达、致远、用友、万户、蓝凌、金和、红帆、海昌、帆软、启莱、正方、信达、飞企互联、广联达、信呼等 |
| **网络设备**    | H3C、华为、思科、D-Link、深信服、TP-Link、锐捷等             |
| **安全设备**    | 奇安信、绿盟、启明、安恒、齐治、宝塔、网康、山石网科等       |
| **Apache 组件** | Spark、Druid、Hadoop、kylin、Dubbo、APISIX、Solr、OFBiz、CloudStack、Airflow 等 |
| **监控设备**    | 海康、大华、宇视、中科智远、Cacti 等                         |

### 2. 丰富漏扫插件（600 + 实战漏洞持续更新）


集成最新1day\nday漏扫插件，支持复杂http请求和反连，根据**指纹命中漏扫插件**，目前支持插件扫描数量如下

海康26个、泛微58个、致远26个、亿赛通39个、金和21个、金蝶11个、宏景20个、广联达14个、飞企互联9个、大华26个、用友7个、万户14个、通达30个、深信服8个，同时支持shiro反序列化、各种组件中间件、Citrix、Confluence、VMware等共计**600+**漏扫插件

### 3. 多协议弱口令检测


支持SSH、MSSQL、MYSQL，RDP、FTP、  PostgreSQL、SMB、Telnet、SNMP、Tomcat、MangoDB、VNC、Oracle各种协议的弱口令检测

### 4. 高效端口扫描

内置 TOP100、TOP500、TOP1000 常用端口列表，可快速适配不同扫描场景需求。



## 🚀 工具使用指南

### 初始化配置

工具首次运行需配置`ceyeApi`和`ceyeDomain`（目前仅支持 ceye 反连平台）

![image](https://github.com/user-attachments/assets/8ff0ecce-603a-4ea9-91cf-c19f72b19ae4)


常见用法，ip.txt可以放域名或者ip，按行读取，支持对单个IP、域名、URL进行扫描


```
scan -h                             #查看帮助
scan --ipfile ip.txt --noping       #读取ip.txt 禁ping扫描
scan -u http://www.example.com      #对单个url扫描
scan -i 192.168.1.0/24 -p top100               #对ip段扫描,使用top100端口
scan -i 192.168.1.1 -x http://127.0.0.1:8080   #对单个ip扫描,设置http代理
dirscan -u http://www.example.com   #对单个url目录扫描
```



### 扫描效果展示

![image](https://github.com/user-attachments/assets/ba15c214-317e-4ab3-8ecc-8e4e5e1d7c32)

![image](https://github.com/user-attachments/assets/7d44833e-00ec-439a-ae65-5e89d33afcc0)





## ⚠️ 免责声明

本工具仅用于**合法授权的安全自查检测**。因传播、利用本工具信息造成的任何直接或间接后果及损失，均由使用者自行承担，作者不承担任何责任。未经网络安全部门及相关机构允许，严禁用于攻击活动或商业用途。使用者需严格遵守《网络安全法》等相关法律法规，违规使用后果自负。

作者保留对工具的修改与解释权。

参考

https://github.com/selinuxG/Golin

https://github.com/shadow1ng/fscan



