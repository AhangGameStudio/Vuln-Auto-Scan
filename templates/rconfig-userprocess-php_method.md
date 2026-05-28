# rConfig userprocess.php 任意用户创建漏洞

## 漏洞描述
rConfig userprocess.php 存在任意用户创建漏洞，发送特定的请求包攻击者可以创建管理员账户登录后台

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
出现漏洞的文件为 userproce.php

```php
<?php

/**
 * Process.php
 * 
 * The Process class is meant to simplify the task of processing
 * user submitted forms, redirecting the user to the correct

## Payloads
```
出现漏洞的原因是对权限设定错误，任何人都可以通过访问这个文件创建管理员用户

发送如下请求包创建管理员用户 testtest，密码为 testtest[@123 ]()
```
