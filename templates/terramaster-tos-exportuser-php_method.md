# TerraMaster TOS exportUser.php 远程命令执行

## 漏洞描述
TerraMaster TOS exportUser.php 文件中存在远程命令执行漏洞

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
出现漏洞的文件 ***exportUser.php***

```php
<?php
    include_once "./app.php"; // [1] autoload classes
    class CSV_Writer{
        ...
    }
    $type = $_GET['type'];
    $csv = new CSV_Writer();

## Payloads
```
在其他文件的代码检查期间，也发现有一种方法可以利用TOS软件中预先存在的类来利用此问题。
位于**include/class/application.class.php**中的PHP类是在运行TOS软件的设备上执行命令的最佳人选。

由于*exportUser.php*没有身份验证控件，因此未经身份验证的攻击者有可能通过提供以下值作为HTTP GET参数来实现代码执行。
```
```
返回200后再次访问
```
