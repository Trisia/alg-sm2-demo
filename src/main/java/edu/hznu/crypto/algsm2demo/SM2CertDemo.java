package edu.hznu.crypto.algsm2demo;


import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

/**
 * SM2 X.509签名制作Demo
 *
 * @author Cliven
 * @date 2018-12-21 14:04
 */
public class SM2CertDemo {

    /**
     * BouncyCastle算法提供者
     */
    private static final Provider BC = new BouncyCastleProvider();

    /**
     * 获取DN(Distinct Name)构造者<br>
     * 来唯一标识一个实体，其功能类似我们平常使用的ID
     * {@see <a href="https://www.ibm.com/support/knowledgecenter/en/SSFKSJ_7.5.0/com.ibm.mq.sec.doc/q009860_.htm"></a>}
     *
     * @return X500NameBuilder
     */
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

    /**
     * 获取扩展密钥用途
     *
     * @return 增强密钥用法ASN.1对象
     * @author Cliven
     * @date 2018-12-21 16:04:58
     */
    public static DERSequence extendedKeyUsage() {
        // 客户端身份认证
        ASN1ObjectIdentifier clientAuth = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.2");
        // 安全电子邮件
        ASN1ObjectIdentifier emailProtection = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.4");
        // 构造容器对象
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(clientAuth);
        vector.add(emailProtection);
        return new DERSequence(vector);
    }

    /**
     * 生成证书文件
     *
     * @param x509Certificate X.509格式证书
     * @param savePath        证书保存路径
     * @throws CertificateEncodingException
     * @throws IOException
     * @author Cliven
     * @date 2018-12-21 17:21:50
     */
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

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, OperatorCreationException, IOException, CertificateException {
        // 生成密钥生成器
        KeyPairGenerator keyPairGenerator = SM2KeyGenerateFactory.generator();
        // 产生密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 证书签名实现类
        ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2")
                .setProvider(BC)
                .build(keyPair.getPrivate());

        // 构造X.509 第3版的证书构建者
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                // 颁发者信息
                createStdBuilder().build()
                // 证书序列号
                , BigInteger.valueOf(Instant.now().toEpochMilli())
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

        // 将证书构造参数装换为X.509证书对象
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(BC)
                .getCertificate(certGen.build(sigGen));
        // 保存为证书文件
        makeCertFile(certificate, Paths.get("test-cert.cer"));
    }
}
