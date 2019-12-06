package edu.hznu.crypto.algsm2demo;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.Security;

/**
 * HMAC - SM3 使用演示Demo
 * <p>
 * HMAC 实现细节请参考
 *
 * <a ref="https://tools.ietf.org/html/rfc2104">https://tools.ietf.org/html/rfc2104</a>
 *
 * @author 权观宇
 * @since 2019-12-06 15:11:43
 */
public class HmacSm3Demo {

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        // 以创建SM3为摘要算法的Hmac
        HMac hMac = new HMac(new SM3Digest());
        byte[] plaintext = "这是待消息签名的原文".getBytes(StandardCharsets.UTF_8);
        // 签名结果值，长度取决于消息签名所使用的摘要算法产生的数据长度（SM3 为 32 byte）
        byte[] sigValue = new byte[hMac.getMacSize()];
        byte[] key = "这是密钥".getBytes(StandardCharsets.UTF_8);
        KeyParameter secret = new KeyParameter(key);
        // 使用密钥初始化
        hMac.init(secret);
        // 类似于SM3函数的使用直接传入原文。
        hMac.update(plaintext, 0, plaintext.length);
        // 计算签名结果
        hMac.doFinal(sigValue, 0);


        System.out.println("原文: \t" + Hex.toHexString(plaintext));
        System.out.println("密钥: \t" + Hex.toHexString(key));
        System.out.println("签名值: \t" + Hex.toHexString(sigValue));
        /*
         * HMAC 最常见的引用就是使用 JWT
         */
    }
}
