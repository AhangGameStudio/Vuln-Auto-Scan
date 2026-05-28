# ShowDoc PageController.class.php 任意文件上传漏洞

## 漏洞描述
ShowDoc 存在任意文件上传漏洞，攻击者通过构造特殊的数据包可以上传恶意文件控制服务器

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
网站首页如下

![](images/202202101919494.png)



构造如下数据包上传php文件



