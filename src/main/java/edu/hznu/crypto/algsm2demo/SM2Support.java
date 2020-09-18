package edu.hznu.crypto.algsm2demo;

import org.bouncycastle.asn1.*;
import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

/**
 * create by Cliven on 2018-07-31 13:48
 * 解析SM2算法的相关参数的工具
 *
 * @author Cliven
 * 其中参数参考《SM2椭圆曲线公钥密码算法推荐曲线参数》
 */
public class SM2Support {

    /**
     * SM2椭圆曲线公钥密码推荐参数
     */
    public static final byte P[] = {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };
    public static final byte A[] = {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
    };
    public static final byte B[] = {
            (byte) 0x28, (byte) 0xE9, (byte) 0xFA, (byte) 0x9E, (byte) 0x9D, (byte) 0x9F, (byte) 0x5E, (byte) 0x34,
            (byte) 0x4D, (byte) 0x5A, (byte) 0x9E, (byte) 0x4B, (byte) 0xCF, (byte) 0x65, (byte) 0x09, (byte) 0xA7,
            (byte) 0xF3, (byte) 0x97, (byte) 0x89, (byte) 0xF5, (byte) 0x15, (byte) 0xAB, (byte) 0x8F, (byte) 0x92,
            (byte) 0xDD, (byte) 0xBC, (byte) 0xBD, (byte) 0x41, (byte) 0x4D, (byte) 0x94, (byte) 0x0E, (byte) 0x93
    };


    public static final byte GX[] = {
            (byte) 0x32, (byte) 0xC4, (byte) 0xAE, (byte) 0x2C, (byte) 0x1F, (byte) 0x19, (byte) 0x81, (byte) 0x19,
            (byte) 0x5F, (byte) 0x99, (byte) 0x04, (byte) 0x46, (byte) 0x6A, (byte) 0x39, (byte) 0xC9, (byte) 0x94,
            (byte) 0x8F, (byte) 0xE3, (byte) 0x0B, (byte) 0xBF, (byte) 0xF2, (byte) 0x66, (byte) 0x0B, (byte) 0xE1,
            (byte) 0x71, (byte) 0x5A, (byte) 0x45, (byte) 0x89, (byte) 0x33, (byte) 0x4C, (byte) 0x74, (byte) 0xC7
    };

    public static final byte GY[] = {
            (byte) 0xBC, (byte) 0x37, (byte) 0x36, (byte) 0xA2, (byte) 0xF4, (byte) 0xF6, (byte) 0x77, (byte) 0x9C,
            (byte) 0x59, (byte) 0xBD, (byte) 0xCE, (byte) 0xE3, (byte) 0x6B, (byte) 0x69, (byte) 0x21, (byte) 0x53,
            (byte) 0xD0, (byte) 0xA9, (byte) 0x87, (byte) 0x7C, (byte) 0xC6, (byte) 0x2A, (byte) 0x47, (byte) 0x40,
            (byte) 0x02, (byte) 0xDF, (byte) 0x32, (byte) 0xE5, (byte) 0x21, (byte) 0x39, (byte) 0xF0, (byte) 0xA0
    };
    /**
     * 阶
     */
    public static final byte N[] = {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0x72, (byte) 0x03, (byte) 0xDF, (byte) 0x6B, (byte) 0x21, (byte) 0xC6, (byte) 0x05, (byte) 0x2B,
            (byte) 0x53, (byte) 0xBB, (byte) 0xF4, (byte) 0x09, (byte) 0x39, (byte) 0xD5, (byte) 0x41, (byte) 0x23
    };

    /**
     * 基点G = （Xg, Yg）
     */
    public static final ECPoint G_POINT = new ECPoint(new BigInteger(1, GX), new BigInteger(1, GY));
    private static final EllipticCurve EllC = new EllipticCurve(new ECFieldFp(new BigInteger(1, P)), new BigInteger(1, A), new BigInteger(1, B));

    public static final java.security.spec.ECParameterSpec SM2_SPEC =
            new java.security.spec.ECParameterSpec(EllC, G_POINT, new BigInteger(1, N), 1);


    /**
     * 解析SM2 类型的公钥，并构造公钥对象
     *
     * @param publicKeyBytes 公钥字节串 格式为 X || Y
     * @return 公钥对象
     * @author Cliven
     * @since 2018-07-31 14:04:16
     */
    public static ECPublicKey parseSM2PublicKey(byte[] publicKeyBytes) {
        if (publicKeyBytes == null || publicKeyBytes.length == 0) {
            throw new IllegalArgumentException("publicKeyBytes is blank!");
        }
        byte[] pX = new byte[32];
        byte[] pY = new byte[32];
        // 从公钥字节中取出两个坐标值字节
        System.arraycopy(publicKeyBytes, 0, pX, 0, 32);
        System.arraycopy(publicKeyBytes, 32, pY, 0, 32);
        // 将坐标值字节转为大数字
        BigInteger bnX = new BigInteger(1, pX);
        BigInteger bnY = new BigInteger(1, pY);
        // 构造公钥点坐标 Pa = （Xa, Ya）
        ECPoint pubPoint = new ECPoint(bnX, bnY);
        // 构造椭圆曲线公钥
        java.security.spec.ECPublicKeySpec ecPublicKeySpec = new java.security.spec.ECPublicKeySpec(pubPoint, SM2_SPEC);
        return new JCEECPublicKey("SM2", ecPublicKeySpec);
    }

    /**
     * 解析SM2 类型的私钥数据，并且构造私钥对象
     *
     * @param privateKeyBytes 私钥字节串
     * @return 私钥对象
     * @author Cliven
     * @since 2018-07-31 14:17:31
     */
    public static ECPrivateKey parseSM2PrivateKey(byte[] privateKeyBytes) {
        if (privateKeyBytes == null || privateKeyBytes.length == 0) {
            throw new IllegalArgumentException("privateKeyBytes is blank!");
        }
        byte[] pD = new byte[32];
        // 从私钥数据中截取出私钥数据 k， k 属于 [1, n - 1]
        System.arraycopy(privateKeyBytes, privateKeyBytes.length - 32, pD, 0, 32);
        BigInteger bnD = new BigInteger(1, pD);
        // 构造椭圆曲线私钥
        java.security.spec.ECPrivateKeySpec ecPriSpec = new java.security.spec.ECPrivateKeySpec(bnD, SM2_SPEC);
        return new JCEECPrivateKey("SM2", ecPriSpec);
    }



    /**
     * 获取 X||Y 格式的公钥字节串
     *
     * @param publicKey 公钥对象
     * @return X||Y 格式的公钥字节串
     * @author Cliven
     * @since 2018-07-31 10:42:43
     */
    public static byte[] getPurePubKey(PublicKey publicKey) throws IOException {
//        ECPublicKey ecPubKey = (ECPublicKey) publicKey;
//        ECPoint ecpoint = ecPubKey.getW();
//        BigInteger x = ecpoint.getAffineX();
//        BigInteger y = ecpoint.getAffineY();
//        byte[] bx = x.toByteArray();
//        byte[] by = y.toByteArray();
//        log.info("bx: {}", Hex.toHexString(bx));
//        log.info("by: {}", Hex.toHexString(by));
//        byte[] res = new byte[64];
//        System.arraycopy(bx, bx.length - 32, res, 0, 32);
//        System.arraycopy(by, by.length - 32, res, 32, 32);
//        return res;
        ASN1Sequence sequence = ASN1Sequence.getInstance(publicKey.getEncoded());

        // 取出公钥所在字段
        byte[] asn1PubKeySrc = sequence.getObjectAt(1).toASN1Primitive().getEncoded();
        DERBitString pubKeyBitString = DERBitString.getInstance(asn1PubKeySrc);
        byte[] puk = pubKeyBitString.getBytes();
        // 公钥格式为 04||X||Y (04为16进制字符，参考《GM/64-2012》)
        return Arrays.copyOfRange(puk, 1, puk.length);
    }


    /**
     * 获取ASN1Encodable 后32Byte，作为数据
     *
     * @param encodable 可编码的ASN1对象
     * @return 后32byte数据
     * @throws IOException 获取字节码时异常
     * @author Cliven
     * @since 2018-07-31 09:49:28
     */
    public static byte[] getSignValuePair(ASN1Encodable encodable) throws IOException {
        byte[] out = new byte[32];
        ASN1Integer pair = ASN1Integer.getInstance(encodable.toASN1Primitive().getEncoded());
        byte[] valueBytes = pair.getValue().toByteArray();
        System.arraycopy(valueBytes, valueBytes.length - 32, out, 0, 32);
        return out;
    }

    /**
     * r || s 类型的数据结构的字节串转ASN1的 字节串
     *
     * @param pureData r || s 类型的数据
     * @return ASN1编码的字节串
     * @throws IOException 获取ASN1编码异常、
     * @author Cliven
     * @since 2018-07-31 16:13:21
     */
    public static byte[] getPureSignData2ASN1(byte[] pureData) throws IOException {
        byte[] r = Arrays.copyOfRange(pureData, 0, 32);
        byte[] s = Arrays.copyOfRange(pureData, 32, pureData.length);

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(new BigInteger(1, r)));
        vector.add(new ASN1Integer(new BigInteger(1, s)));
        DERSequence sequence = new DERSequence(vector);
        return sequence.getEncoded();
    }

    /**
     * 16进制字符串转int
     *
     * @param hex 16进制字符串
     * @return 数字
     * @author Cliven
     * @since 2018-08-01 09:24:56
     */
    public static int hexStr2int(String hex) {
        byte[] len = Hex.decode(hex);
        return new BigInteger(1, len).intValue();
    }
}
