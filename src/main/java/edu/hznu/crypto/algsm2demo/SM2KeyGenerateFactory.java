package edu.hznu.crypto.algsm2demo;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

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
     * @author Cliven
     * @date 2019-6-10 15:56:36
     */
    public static KeyPairGenerator generator() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

//        // 获取SM2 椭圆曲线推荐参数
//        X9ECParameters ecParameters = GMNamedCurves.getByName("sm2p256v1");
//        // 构造EC 算法参数
//        ECNamedCurveParameterSpec sm2Spec = new ECNamedCurveParameterSpec(
//                // 设置SM2 算法的 OID
//                GMObjectIdentifiers.sm2p256v1.toString()
//                // 设置曲线方程
//                , ecParameters.getCurve()
//                // 椭圆曲线G点
//                , ecParameters.getG()
//                // 大整数N
//                , ecParameters.getN());
//        // 创建 密钥对生成器
//        final KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
//        // 使用SM2的算法区域初始化密钥生成器
//        kpg.initialize(sm2Spec, new SecureRandom());
//        return gen;

        /*
         * 上面过程为原始构造过程参考，BC已经为我们封装好了
         * 只需要下面三行代码即可
         */
        // 获取SM2椭圆曲线的参数
        final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        // 获取一个椭圆曲线类型的密钥对生成器
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        // 使用SM2参数初始化生成器
        kpg.initialize(sm2Spec);
        return kpg;
    }
}
