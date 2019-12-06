package edu.hznu.crypto.algsm2demo.sm4;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;

import java.util.Arrays;

/**
 * @author 权观宇
 * @date 2019-02-25 12:33
 */
public class TestSm4 {
    /**
     * 输入明文
     */
    private static final String plaintextStr = "01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10";
    /**
     * 输入密钥
     */
    private static final String keyStr = "01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10";
    /**
     * 输出密文 单次
     */
    private static final String ciphertextStr1 = "68 1E DF 34 D2 06 96 5E 86 B3 E9 4F 53 6E 42 46";

    /**
     * 输出密文 1 000 000 次
     */
    private static final String ciphertextStr1000000 = "59 52 98 C7 C6 FD 27 1F 04 02 F8 04 C3 3D 3F 66";

    public static void testSigle() {
        // 输入明文
        System.out.println("输入明文：" + plaintextStr);
        byte[] plaintext = HexBin.decode(
                plaintextStr
                        .replace(" ", ""));
        // 输入密钥
        byte[] key = HexBin.decode(
                keyStr
                        .replace(" ", ""));
        System.out.println("输入密钥：" + keyStr);

        // 输出密文
        byte[] ciphertext = HexBin.decode(
                ciphertextStr1
                        .replace(" ", ""));
        System.out.println("轮密钥与每轮输出状态：");
        // 加密
        byte[] res = Sm4.encrypt(plaintext, key);
        System.out.println();
        System.out.println("输出密文：" + HexBin.encode(res));
        // 解密
        res = Sm4.decrypt(res, key);
        // 比对原文
        System.out.println("Result is right: " + Arrays.equals(plaintext, res));
    }

    public static void test1000000() {
        // 输入明文
        System.out.println("输入明文：" + plaintextStr);
        byte[] plaintext = HexBin.decode(
                plaintextStr
                        .replace(" ", ""));
        // 输入密钥
        byte[] key = HexBin.decode(
                keyStr
                        .replace(" ", ""));
        System.out.println("输入密钥：" + keyStr);

        // 输出密文
        byte[] ciphertext = HexBin.decode(
                ciphertextStr1000000
                        .replace(" ", ""));

        byte[] res = plaintext;
        // 加密 1000 00 次
        long start = System.currentTimeMillis();
        for (int i = 0; i < 10000000; i++) {
            res = Sm4.encrypt(res, key);
        }
        System.out.println("输出密文：" + HexBin.encode(res));
        System.out.println("Result is right: " + Arrays.equals(res, ciphertext));
        System.out.printf("Cost time: %d ms\n", System.currentTimeMillis() - start);
    }

    public static void main(String[] args) {
        test1000000();
//        testSigle();
    }
}
