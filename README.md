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
// 获取SM2 椭圆曲线推荐参数
X9ECParameters ecParameters = GMNamedCurves.getByName("sm2p256v1");
// 构造EC 算法参数
ECNamedCurveParameterSpec sm2Spec = new ECNamedCurveParameterSpec(
        // 设置SM2 算法的 OID
        GMObjectIdentifiers.sm2p256v1.toString()
        // 设置曲线方程
        , ecParameters.getCurve()
        // 椭圆曲线G点
        , ecParameters.getG()
        // 大整数N
        , ecParameters.getN());
// 创建 密钥对生成器
KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());

// 使用SM2的算法区域初始化密钥生成器
gen.initialize(sm2Spec, new SecureRandom());
// 获取密钥对
KeyPair keyPair = gen.generateKeyPair();
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