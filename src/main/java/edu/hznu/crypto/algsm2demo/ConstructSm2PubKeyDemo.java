package edu.hznu.crypto.algsm2demo;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;

/**
 * 构造SM2 公钥并验签
 *
 * @author 权观宇
 * @since 2020-09-18 10:18:27
 */
public class ConstructSm2PubKeyDemo {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // 格式为 X|Y 拼接的公钥（32 + 32）
        String XY = "B9A3F7DABFFCFED26345A02DA511E491C17462B91CCF54A010B49A2FE4C8AC7C298192184075F1BD5DBE24BFE00AC75EEC25FC85DA4E8F002C8F4F292EE638FD";
        // 构造签名公钥
        ECPublicKey sm2Pub = SM2Support.parseSM2PublicKey(Hex.decode(XY));
        String sigVal = "MEQCIBCbdfxcarmaeMjolXoUA1kxg7bBPC28UEFUZlhg3BzrAiB0kGAF6CSikKeGOWPwEw4RCUqVXScnTi4P7wM75BK1EA==";

        // 生成SM2sign with sm3 签名验签算法实例
        Signature signature = Signature.getInstance("SM3withSm2", new BouncyCastleProvider());
        signature.initVerify(sm2Pub);
        // 原文为2048字节0
        signature.update(new byte[2048]);
        boolean verify = signature.verify(Base64.decode(sigVal));
        System.out.println(verify);
    }
}
