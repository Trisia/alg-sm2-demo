# SM2密码算法 JAVA 调用Demo

[TOC]

## Before Start

SM2算法使用请参考：[《GMT 0009-2012 SM2密码算法使用规范 》](http://www.gmbz.org.cn/main/viewfile/2018011001400692565.html)

---

在`bouncycastle`  - `1.57`版本之后，加入了对 我国的**SM2、SM3、SM4算法的支持**。

[Bouncycastle releasenotes](https://www.bouncycastle.org/releasenotes.html)

![BC版本日志](https://img-blog.csdnimg.cn/20181220102556126.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3ExMDA5MDIwMDk2,size_16,color_FFFFFF,t_70)

### Build with Maven

[适配JDK 1.5 版本](https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on/1.60)
```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk15on</artifactId>
    <version>1.60</version>
</dependency>
```

## QuickStart

### 密钥对生成

SM2 非对称算法密钥对生成。
```java
// 获取SM2椭圆曲线的参数
final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
// 获取一个椭圆曲线类型的密钥对生成器
final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
// 使用SM2参数初始化生成器
kpg.initialize(sm2Spec);

// 使用SM2的算法区域初始化密钥生成器
kpg.initialize(sm2Spec, new SecureRandom());
// 获取密钥对
KeyPair keyPair = kpg.generateKeyPair();
```

关于椭圆曲线的推荐参数请参考  [IETF draft-shen-sm2-ecdsa-02 #appendix-D](https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02#appendix-D)

> 在BC中已经为构造了SM2算法参数，并提供算法OID，请参考：<br>
> [国密算法OID及意义 ](http://gmssl.org/docs/oid.html)<br>
> [国密算法OID 源码](https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/asn1/gm/GMObjectIdentifiers.java)<br>
> [SM2算法推荐参数 源码](https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/asn1/gm/GMNamedCurves.java)

### 签名验签

产生了密钥对之后，就可以使用JAVA security 提供的一些标准化的接口来完成签名验签操作。
```java
/*
获取公私钥
 */
PublicKey publicKey = keyPair.getPublic();
PrivateKey privateKey = keyPair.getPrivate();

// 生成SM2sign with sm3 签名验签算法实例
Signature signature = Signature.getInstance(
				 GMObjectIdentifiers.sm2sign_with_sm3.toString()
				, new BouncyCastleProvider());

/*
签名
 */
// 签名需要使用私钥，使用私钥 初始化签名实例
signature.initSign(privateKey);
// 签名原文
byte[] plainText = "Hello world".getBytes(StandardCharsets.UTF_8);
// 写入签名原文到算法中
signature.update(plainText);
// 计算签名值
byte[] signatureValue = signature.sign();
System.out.println("signature: \n" + Hex.toHexString(signatureValue));

/*
验签
 */
// 签名需要使用公钥，使用公钥 初始化签名实例
signature.initVerify(publicKey);
// 写入待验签的签名原文到算法中
signature.update(plainText);
// 验签
System.out.println("Signature verify result: " + signature.verify(signatureValue));
```

> 你可以在 [国密算法OID ](http://gmssl.org/docs/oid.html)中找到需要算法的OID字符串。
> 如： SM2Sign-with-SM3  `1.2.156.10197.1.501`

---

# JAVA SM2 数字证书生成Demo

## Before Start

X.509数字证书请参考：

[RFC5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://tools.ietf.org/html/rfc5280)

中文版的简要介绍可以参考这篇文章 [Agzs . X509证书--ANS1结构](https://blog.csdn.net/code_segment/article/details/77163652)

如果还未能**生成SM2密钥对**请先阅读 
- [JAVA SM2 密钥生成 签名验签](https://blog.csdn.net/q1009020096/article/details/85115698)

### Build with Maven

- [bcprov](https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on/1.60)
- [bcpkix](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15on)
```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk15on</artifactId>
    <version>1.60</version>
</dependency>

<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpkix-jdk15on</artifactId>
    <version>1.60</version>
</dependency>
```

## QuickStart

[Github](https://github.com/Trisia/alg-sm2-demo)

```java
/**
 * BouncyCastle算法提供者
 */
private static final Provider BC = new BouncyCastleProvider();
```

### 生成自签名公私钥对

`keyPairGenerator`的构造请参考 [JAVA SM2 密钥生成 签名验签](https://blog.csdn.net/q1009020096/article/details/85115698)
```java
// 产生密钥对
KeyPair keyPair = keyPairGenerator.generateKeyPair();
```

### 证书签名算法算法提供者

在制作证书时需要使用到签名算法签名证书中部分数据区域，国密类型的数字证书使用的签名算法是`SM3withSM2`，这里使用私钥创建算法提供容器。
```java
ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2")
        .setProvider(BC)
        .build(keyPair.getPrivate());
```

### 设置证书信息

设置证书的基本数据：使用者信息、颁发者信息、证书序号、证书生效日期、证书失效日期，以及证书扩展属性。

#### 标识信息构造（DN）

上面提到的使用者信息、颁发者信息，使用Distinct Name的方式来描述。

关于DN中的各个字段的含义请参考 [IBM Previous Next
Distinguished Names](https://www.ibm.com/support/knowledgecenter/en/SSFKSJ_7.5.0/com.ibm.mq.sec.doc/q009860_.htm)

实际上简单来讲就是，用来确定“实体” 身份/信息 的一系列**列键值对**组成的字符串。

这里的键是一个`ASN1ObjectIdentifier`，实际上Bouncycastle已经为我们把需要的大多键都已经列好了，我们只要使用这个类`org.bouncycastle.asn1.x500.style.BCStyle`的静态变量就可以。

```java
private static X500NameBuilder createStdBuilder() {
    X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
    // 国家代码
    builder.addRDN(BCStyle.C, "CN");
    // 组织
    builder.addRDN(BCStyle.O, "HZNU");
    // 省份
    builder.addRDN(BCStyle.ST, "Zhejiang");
    // 地区
    builder.addRDN(BCStyle.L, "Hangzhou");
    return builder;
}
```
然后我们就可以使用`X500NameBuilder`的`build()`方法构造对应的DN了。

> [BCStyle 源码请参考](https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/asn1/x500/style/BCStyle.java)，也可以使用与该文件中处于同级目录的[RFC4519Style](https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/asn1/x500/style/RFC4519Style.java)

#### 获取扩展密钥用途构造（可选）
如果需要设置证书的扩展密钥用途，可以使用`DERSequence`来构造一个拓展密钥用途的序列。

[拓展密钥用途](https://tools.ietf.org/html/rfc5280#section-4.2.1.12)

```java
public static DERSequence extendedKeyUsage() {
        // 构造容器对象
        ASN1EncodableVector vector = new ASN1EncodableVector();
        // 客户端身份认证
        vector.add(KeyPurposeId.id_kp_clientAuth);
        // 安全电子邮件
        vector.add(KeyPurposeId.id_kp_emailProtection);
        return new DERSequence(vector);
}
```

> 扩展密钥用途的各个OID Bouncycastle 已经为我们提供，请参考[KeyPurposeId](https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/asn1/x509/KeyPurposeId.java)

#### 证书信息构造

接下来可以使用`X509v3CertificateBuilder` 来设置证书的基本参数，下面列举基本一些证书参数和扩展参数的设置方式。
```java
// 构造X.509 第3版的证书构建者
X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
        // 颁发者信息
        createStdBuilder().build()
        // 证书序列号
        , BigInteger.valueOf(1)
        // 证书生效日期
        , new Date(System.currentTimeMillis() - 50 * 1000)
        // 证书失效日期
        , new Date(System.currentTimeMillis() + 50 * 1000)
        // 使用者信息（PS：由于是自签证书，所以颁发者和使用者DN都相同）
        , createStdBuilder().build()
        // 证书公钥
        , keyPair.getPublic())
        /*
        设置证书扩展
        证书扩展属性，请根据需求设定，参数请参考 《RFC 5280》
         */
        // 设置密钥用法
        .addExtension(Extension.keyUsage, false
                , new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation))
        // 设置扩展密钥用法：客户端身份认证、安全电子邮件
        .addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage())
        // 基础约束,标识是否是CA证书，这里false标识为实体证书
        .addExtension(Extension.basicConstraints, false, new BasicConstraints(false))
        // Netscape Cert Type SSL客户端身份认证
        .addExtension(MiscObjectIdentifiers.netscapeCertType, false, new NetscapeCertType(NetscapeCertType.sslClient));
```

> 更多 Netscape Cert Type 类型请参考：[NetscapeCertType](https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/asn1/misc/NetscapeCertType.java)


#### X.509格式证书对象生成

通过使用证书构造好的信息，接下就能够生成x509格式的证书对象
```java
// 将证书构造参数装换为X.509证书对象
X509Certificate certificate = new JcaX509CertificateConverter()
        .setProvider(BC)
        .getCertificate(certGen.build(sigGen));
```

#### 保存证书

如果需要永久的保存刚才生成的这份证书，那么我们需要对这个证书进行序列化，常见的证书序列化是将ASN.1编码的证书对象，进行BASE64编码，这样证书更加便于网络传输。
```java
public static void makeCertFile(X509Certificate x509Certificate, Path savePath) throws CertificateEncodingException, IOException {
    if (Files.exists(savePath)) {
        // 删除已存在文件
        Files.deleteIfExists(savePath);
    }
    // 创建文件
    Files.createFile(savePath);
    // 获取ASN.1编码的证书字节码
    byte[] asn1BinCert = x509Certificate.getEncoded();
    // 编码为BASE64 便于传输
    byte[] base64EncodedCert = Base64.encode(asn1BinCert);
    // 写入文件
    Files.write(savePath, base64EncodedCert);
}
```

给与文件名称，调用保存（常见的DER编码的证书后缀名为`.cer`）。
```java
// 保存为证书文件
makeCertFile(certificate, Paths.get("test-cert.cer"));
```

![生成的证书截图](https://img-blog.csdnimg.cn/2018122118300475.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3ExMDA5MDIwMDk2,size_16,color_FFFFFF,t_70)


### ASN.1 结构解析工具

[asn1js](https://github.com/lapo-luchini/asn1js)


通过该工具，输入证书的BASE64编码的字符串，我们能够快速分析证书的结构，以及各种字段。
![截图](https://img-blog.csdnimg.cn/20181221184229421.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3ExMDA5MDIwMDk2,size_16,color_FFFFFF,t_70)

## 致谢

在编写代码时参考了下面的例子：
- [Java Code Examples . X509v3CertificateBuilder.https://www.programcreek.com/java-api-examples/?api=org.bouncycastle.cert.X509v3CertificateBuilder](https://www.programcreek.com/java-api-examples/?api=org.bouncycastle.cert.X509v3CertificateBuilder)
- [github . bouncycastle . https://github.com/bcgit/bc-java/blob/master/pkix/src/test/jdk1.1/org/bouncycastle/cert/test/CertTest.java](https://github.com/bcgit/bc-java/blob/master/pkix/src/test/jdk1.1/org/bouncycastle/cert/test/CertTest.java)

参考列表：

- [RFC5280 . Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile . https://tools.ietf.org/html/rfc5280)](https://tools.ietf.org/html/rfc5280)
- [Agzs . X509证书--ANS1结构 . https://blog.csdn.net/code_segment/article/details/77163652](https://blog.csdn.net/code_segment/article/details/77163652)
-  [IBM . Previous Next
Distinguished Names . https://www.ibm.com/support/knowledgecenter/en/SSFKSJ_7.5.0/com.ibm.mq.sec.doc/q009860_.htm](https://www.ibm.com/support/knowledgecenter/en/SSFKSJ_7.5.0/com.ibm.mq.sec.doc/q009860_.htm)