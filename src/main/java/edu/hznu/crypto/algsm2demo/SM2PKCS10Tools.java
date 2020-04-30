package edu.hznu.crypto.algsm2demo;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.security.*;

/**
 * 生成证书请求文件（PCSK10）
 *
 * <a ref="https://tools.ietf.org/html/rfc2986">rfc2986</a>
 *
 * @author 权观宇
 * @since 2019-11-26 16:25:03
 */
public class SM2PKCS10Tools {

    /**
     * @return 证书请求识别名称 （也就是证书的Subject）
     */
    public static X500Name dn() {
        return new X500NameBuilder()
                // 国家代码
                .addRDN(BCStyle.C, "CN")
                // 组织
                .addRDN(BCStyle.O, "HZNU")
                // 省份
                .addRDN(BCStyle.ST, "Zhejiang")
                // 地区
                .addRDN(BCStyle.L, "Hangzhou")
                // 通用名称
                .addRDN(BCStyle.CN, "Cluster Node Certificate")
                .build();
    }

    /**
     * 生成SM2密钥对的证书请求（pkcs10格式）
     * <p>
     * 参考资自 {@link org.bouncycastle.cert.test.PKCS10Test#generationTest}
     *
     * <a ref="https://github.com/bcgit/bc-java/blob/master/pkix/src/test/java/org/bouncycastle/cert/test/BcPKCS10Test.java">BcPKCS10Test.java</a>
     *
     * @param kp      SM2密钥对
     * @param subject 证书使用者
     * @return 证书请求
     * @throws OperatorCreationException
     */
    public static PKCS10CertificationRequest generate(KeyPair kp, X500Name subject) throws OperatorCreationException {
        return generate("SM3withSM2", kp, subject);

    }

    public static PKCS10CertificationRequest generate(String alg, KeyPair kp, X500Name subject) throws OperatorCreationException {
        // 构造请求信息，主要是由“实体”的DN和公钥构成
        PKCS10CertificationRequestBuilder requestBuilder =
                new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());
        // 使用“实体”私钥对请求的信息进行签名,然后组装成ASN.1对象
        return requestBuilder.build(
                new JcaContentSignerBuilder(alg)
                        .setProvider("BC")
                        .build(kp.getPrivate()));

    }

    /**
     * 验证PKCS10
     *
     * @param p10Base64 Base64 编码PKCS10 DER
     * @return true - 通过验证；false - 签名值不对
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws OperatorCreationException
     * @throws PKCSException
     */
    public static boolean verifyP10(String p10Base64) throws IOException, NoSuchAlgorithmException, InvalidKeyException, OperatorCreationException, PKCSException {
        // 解码
        byte[] p10Der = Base64.decode(p10Base64);
        JcaPKCS10CertificationRequest req = new JcaPKCS10CertificationRequest(p10Der).setProvider("BC");
        // 取出证书请求中的公钥
        PublicKey publicKey = req.getPublicKey();
        // 签名验证
        return req.isSignatureValid(
                new JcaContentVerifierProviderBuilder()
                        .setProvider("BC")
                        .build(publicKey));
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // 1. 生成SM2密钥对
        KeyPair kp = SM2KeyGenerateFactory.generator().generateKeyPair();
        // 2. 构造使用者DN
        X500Name subject = dn();
        // 3. 生成证书请求（P10），然后进行Base64编码
        PKCS10CertificationRequest req = generate(kp, subject);
        String base64 = Base64.toBase64String(req.getEncoded());
        System.out.printf("证书请求P10：\n\t%s\n", base64);

        boolean pass = verifyP10(base64);
        System.out.println("PKCS10 验证：" + pass);
    }

}
