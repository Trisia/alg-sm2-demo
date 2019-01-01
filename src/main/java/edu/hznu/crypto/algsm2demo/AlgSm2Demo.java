package edu.hznu.crypto.algsm2demo;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * SM2 算法 Demo
 *
 * @author Cliven
 * @date 2018-12-20 10:42:22
 */
public class AlgSm2Demo {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
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
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // ------------------------ SM2未压缩公钥 ----------------------------
        // 椭圆曲线公钥的点坐标
        ECPoint pubKeyPointQ = ((BCECPublicKey) publicKey).getQ();
        System.out.println("X: \n" + pubKeyPointQ.getXCoord());
        System.out.println("Y: \n" + pubKeyPointQ.getYCoord());
        // 将其表示为SM2未压缩的公钥为
        System.out.println("SM2 public key: \n"
                + "04"
                + pubKeyPointQ.getXCoord().toString()
                + pubKeyPointQ.getYCoord().toString()
        );
        // ------------------------ SM2未压缩公钥 -------------------------------

        System.out.println("Public key: \n" + Hex.toHexString(publicKey.getEncoded()));
        System.out.println("Private key: \n" + Hex.toHexString(privateKey.getEncoded()));

        // 生成SM2sign with sm3 签名验签算法实例
        Signature signature = Signature.getInstance("SM3withSm2", new BouncyCastleProvider());

        /*
        签名
         */
        // 签名需要使用私钥，使用私钥 初始化签名实例
        signature.initSign(privateKey);
        // 签名原文
        byte[] plainText = "你好".getBytes(StandardCharsets.UTF_8);
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
    }
}
