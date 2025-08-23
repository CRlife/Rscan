# 自动化漏扫工具、外网打点、内网扫描



前言

最近一直在做内网渗透，内网常见的工具fscan想必再也熟悉不过，但是发现一些企业内网中用市面一些工具已经很难达到预期效果，要么是出洞率太低，要么是效率太低，拿fscan为例，内置漏洞插件已经长时间没更新，指纹识别成功率太低，导致错过很多已有漏洞，面对企业大量内网资产进行梳理时，也鞭长莫及，所以观察到github大佬写的一个项目非常不错，具备可视化输出和资产梳理的功能，值得借鉴，但是这个工具比较综合，并不是一款偏向渗透化的工具，所以就参照大佬项目编写了一个漏扫工具。



## 内置600种指纹识别，规则2000+


支持hash、body、header等全面指纹识别

|                |                                                              |
| -------------- | :----------------------------------------------------------: |
| **OA系统**     | 泛微、通达、致远、用友、万户、蓝凌、金和、红帆、海昌、帆软、启莱、正方、信达、飞企互联、广联达、信呼等 |
| **网络设备**   |       H3C、华为、思科、D-Link、深信服、TP-Link、锐捷等       |
| **安全设备**   |    奇安信、绿盟、启明、安恒、齐治、宝塔、网康、山石网科等    |
| **Apache组件** | Spark、Druid、Hadoop、kylin、Dubbo、APISIX、Solr、OFBiz、CloudStack、Airflow等 |
| **监控设备**   |             海康、大华、宇视、中科智远、Cacti等              |

和其他各种CMS系统ERP系统中间件等，由于数量太多，这里不列举，指纹准确率达到95%以上


## 内置600+漏扫插件


集成最新1day\nday漏扫插件，支持复杂http请求和反连，根据**指纹命中漏扫插件**，目前支持插件扫描数量如下

海康26个、泛微58个、致远26个、亿赛通39个、金和21个、金蝶11个、宏景20个、广联达14个、飞企互联9个、大华26个、用友7个、万户14个、通达30个、深信服8个，同时支持shiro反序列化、各种组件中间件、Citrix、Confluence、VMware等共计**500+**漏扫插件

还有很多指纹漏洞插件没有加入，后续持续加入


## 支持弱口令检测


支持SSH、MSSQL、MYSQL，RDP、FTP、  PostgreSQL、SMB、Telnet、  Tomcat、MangoDB、VNC、Oracle各种协议的弱口令检测


## 端口扫描


内置TOP100端口、TOP500端口、TOP1000端口


## 工具使用


工具首次运行需要配置ceyeApi 和 ceyeDomain，目前仅支持ceye反连平台

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

![image](https://github.com/user-attachments/assets/ba15c214-317e-4ab3-8ecc-8e4e5e1d7c32)



![image](https://github.com/user-attachments/assets/7d44833e-00ec-439a-ae65-5e89d33afcc0)





## 免责声明


该工具仅用于安全自查检测

由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。

本人拥有对此工具的修改和解释权。未经网络安全部门及相关部门允许，不得善自使用本工具进行任何攻击活动，不得以任何方式将其用于商业目的。

该工具只用于授权测试，请勿用于非法用途，请遵守网络安全法，否则后果作者概不负责。



参考：

https://github.com/selinuxG/Golin

https://github.com/shadow1ng/fscan








