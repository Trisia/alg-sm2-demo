package edu.hznu.crypto.algsm2demo;

import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

/**
 * 自签名密钥存储
 *
 * @author 权观宇
 * @since 2019-11-26 14:31:23
 */
public class SM2CARootKeyStoreDemo {

    /**
     * @return 根证书DN
     */
    private static X500Name dn() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        // 国家代码
        builder.addRDN(BCStyle.C, "CN");
        // 组织
        builder.addRDN(BCStyle.O, "HZNU");
        // 省份
        builder.addRDN(BCStyle.ST, "Zhejiang");
        // 地区
        builder.addRDN(BCStyle.L, "Hangzhou");
        // 通用名称
        builder.addRDN(BCStyle.CN, "Cluster CA ROOT Certificate");
        return builder.build();
    }

    /**
     * 产生根证书
     *
     * @param keyPair 密钥对
     * @return 证书对象
     * @throws CertIOException
     * @throws CertificateException
     * @throws OperatorCreationException
     */
    public static X509Certificate genRootCert(KeyPair keyPair) throws CertIOException, CertificateException, OperatorCreationException {
        // 证书签名实现类
        ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2")
                .setProvider("BC")
                .build(keyPair.getPrivate());

        // 构造X.509 第3版的证书构建者
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                // 颁发者信息
                dn()
                // 证书序列号
                , BigInteger.valueOf(Instant.now().toEpochMilli())
                // 证书生效日期
                , new Date(System.currentTimeMillis() - 50 * 1000)
                // 证书失效日期
                , new Date(System.currentTimeMillis() + 50 * 1000)
                // 使用者信息（PS：由于是自签证书，所以颁发者和使用者DN都相同）
                , dn()
                // 证书公钥
                , keyPair.getPublic())
                /*
                设置证书扩展
                证书扩展属性，请根据需求设定，参数请参考 《RFC 5280》
                 */
                // 设置密钥用法
                .addExtension(Extension.keyUsage, false
                        , new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation))
                // 设置扩展密钥用法：客户端身份认证
                .addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth))
                // 基础约束,标识是否是CA证书，这里true 表明是CA证书
                .addExtension(Extension.basicConstraints, false, new BasicConstraints(true))
                // Netscape Cert Type SSL客户端身份认证
                .addExtension(MiscObjectIdentifiers.netscapeCertType, false, new NetscapeCertType(NetscapeCertType.sslClient));

        // 将证书构造参数装换为X.509证书对象
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certGen.build(sigGen));
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        File file = new File("ROOT.p12");
        if (file.exists()) {
            file.delete();
        }
        // 1. 产生密钥对
        KeyPair pk = SM2KeyGenerateFactory.generator().generateKeyPair();
        // 2. 产生自签证书
        X509Certificate rootCert = genRootCert(pk);
        // 3. 以KeyStore保存
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");
        // 3.1 初始化
        store.load(null, null);
        char[] pwd = "123456".toCharArray();
        // 3.2 写入证书以及公钥
        store.setKeyEntry("private", pk.getPrivate(), pwd, new Certificate[]{rootCert});
        try (FileOutputStream out = new FileOutputStream(file)) {
            // 3.3 加密写入文件
            store.store(out, pwd);
        }
    }
}
