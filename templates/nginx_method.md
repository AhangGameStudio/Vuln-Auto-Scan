# Nginx 配置错误漏洞

## 漏洞描述


## 危害等级
LOW

## 参考链接

## 漏洞复现方法
### 错误1  CRLF注入漏洞

Nginx会将`$uri`进行解码，导致传入`%0a%0d`即可引入换行符，造成CRLF注入漏洞。

错误的配置文件示例（原本的目的是为了让http的请求跳转到https上）：

```
location / {
    return 302 https://$host$uri;
}

## Payloads
```
location / {
    return 302 https://$host$uri;
}
```
