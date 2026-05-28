# Nginx 解析漏洞

## 漏洞描述
Nginx解析漏洞复现。

版本信息：

- Nginx 1.x 最新版
- PHP 7.x最新版

由此可知，该漏洞与Nginx、php版本无关，属于用户配置不当造成的解析漏洞。

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
正常显示：

![image-20220228101951322](images/202202281019435.png)

增加`/.php`后缀，被解析成PHP文件：

![image-20220228102009950](images/202202281020083.png)

访问`http://your-ip/index.php`可以测试上传功能，上传代码不存在漏洞，但利用解析漏洞即可getshell。


## Payloads
```
copy 1.jpg/b+1.php/a 2.jpg
```
