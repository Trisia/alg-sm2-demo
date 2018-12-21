package edu.hznu.crypto.algsm2demo;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * SM2密钥对生成器
 *
 * @author Cliven
 * @date 2018-12-21 14:05
 */
public class SM2KeyGenerateFactory {
    /**
     * 获取SM2密钥对生成器
     *
     * @return SM2密钥对生成器
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @author Cliven
     * @date 2018-12-21 14:08:35
     */
    public static KeyPairGenerator generator() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
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
        return gen;
    }
}
