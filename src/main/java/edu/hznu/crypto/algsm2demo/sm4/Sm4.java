package edu.hznu.crypto.algsm2demo.sm4;


import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;

/**
 * @author 权观宇
 * @date 2019-02-24 15:48
 */
public class Sm4 {

    /**
     * GM/T 0002-2012 6.5 合成变换T Sbox 数据
     * <p>
     * 输入EF，表示第E行和第F列值 -> Sbox[EF] = 84
     */
    private static byte[] Sbox = {
            //                  0            1            2            3            4            5            6            7            8            9            A            B            C            D            E            F
            /* 0 */     (byte) 0xd6, (byte) 0x90, (byte) 0xe9, (byte) 0xfe, (byte) 0xcc, (byte) 0xe1, (byte) 0x3d, (byte) 0xb7, (byte) 0x16, (byte) 0xb6, (byte) 0x14, (byte) 0xc2, (byte) 0x28, (byte) 0xfb, (byte) 0x2c, (byte) 0x05,
            /* 1 */     (byte) 0x2b, (byte) 0x67, (byte) 0x9a, (byte) 0x76, (byte) 0x2a, (byte) 0xbe, (byte) 0x04, (byte) 0xc3, (byte) 0xaa, (byte) 0x44, (byte) 0x13, (byte) 0x26, (byte) 0x49, (byte) 0x86, (byte) 0x06, (byte) 0x99,
            /* 2 */     (byte) 0x9c, (byte) 0x42, (byte) 0x50, (byte) 0xf4, (byte) 0x91, (byte) 0xef, (byte) 0x98, (byte) 0x7a, (byte) 0x33, (byte) 0x54, (byte) 0x0b, (byte) 0x43, (byte) 0xed, (byte) 0xcf, (byte) 0xac, (byte) 0x62,
            /* 3 */     (byte) 0xe4, (byte) 0xb3, (byte) 0x1c, (byte) 0xa9, (byte) 0xc9, (byte) 0x08, (byte) 0xe8, (byte) 0x95, (byte) 0x80, (byte) 0xdf, (byte) 0x94, (byte) 0xfa, (byte) 0x75, (byte) 0x8f, (byte) 0x3f, (byte) 0xa6,
            /* 4 */     (byte) 0x47, (byte) 0x07, (byte) 0xa7, (byte) 0xfc, (byte) 0xf3, (byte) 0x73, (byte) 0x17, (byte) 0xba, (byte) 0x83, (byte) 0x59, (byte) 0x3c, (byte) 0x19, (byte) 0xe6, (byte) 0x85, (byte) 0x4f, (byte) 0xa8,
            /* 5 */     (byte) 0x68, (byte) 0x6b, (byte) 0x81, (byte) 0xb2, (byte) 0x71, (byte) 0x64, (byte) 0xda, (byte) 0x8b, (byte) 0xf8, (byte) 0xeb, (byte) 0x0f, (byte) 0x4b, (byte) 0x70, (byte) 0x56, (byte) 0x9d, (byte) 0x35,
            /* 6 */     (byte) 0x1e, (byte) 0x24, (byte) 0x0e, (byte) 0x5e, (byte) 0x63, (byte) 0x58, (byte) 0xd1, (byte) 0xa2, (byte) 0x25, (byte) 0x22, (byte) 0x7c, (byte) 0x3b, (byte) 0x01, (byte) 0x21, (byte) 0x78, (byte) 0x87,
            /* 7 */     (byte) 0xd4, (byte) 0x00, (byte) 0x46, (byte) 0x57, (byte) 0x9f, (byte) 0xd3, (byte) 0x27, (byte) 0x52, (byte) 0x4c, (byte) 0x36, (byte) 0x02, (byte) 0xe7, (byte) 0xa0, (byte) 0xc4, (byte) 0xc8, (byte) 0x9e,
            /* 8 */     (byte) 0xea, (byte) 0xbf, (byte) 0x8a, (byte) 0xd2, (byte) 0x40, (byte) 0xc7, (byte) 0x38, (byte) 0xb5, (byte) 0xa3, (byte) 0xf7, (byte) 0xf2, (byte) 0xce, (byte) 0xf9, (byte) 0x61, (byte) 0x15, (byte) 0xa1,
            /* 9 */     (byte) 0xe0, (byte) 0xae, (byte) 0x5d, (byte) 0xa4, (byte) 0x9b, (byte) 0x34, (byte) 0x1a, (byte) 0x55, (byte) 0xad, (byte) 0x93, (byte) 0x32, (byte) 0x30, (byte) 0xf5, (byte) 0x8c, (byte) 0xb1, (byte) 0xe3,
            /* A */     (byte) 0x1d, (byte) 0xf6, (byte) 0xe2, (byte) 0x2e, (byte) 0x82, (byte) 0x66, (byte) 0xca, (byte) 0x60, (byte) 0xc0, (byte) 0x29, (byte) 0x23, (byte) 0xab, (byte) 0x0d, (byte) 0x53, (byte) 0x4e, (byte) 0x6f,
            /* B */     (byte) 0xd5, (byte) 0xdb, (byte) 0x37, (byte) 0x45, (byte) 0xde, (byte) 0xfd, (byte) 0x8e, (byte) 0x2f, (byte) 0x03, (byte) 0xff, (byte) 0x6a, (byte) 0x72, (byte) 0x6d, (byte) 0x6c, (byte) 0x5b, (byte) 0x51,
            /* C */     (byte) 0x8d, (byte) 0x1b, (byte) 0xaf, (byte) 0x92, (byte) 0xbb, (byte) 0xdd, (byte) 0xbc, (byte) 0x7f, (byte) 0x11, (byte) 0xd9, (byte) 0x5c, (byte) 0x41, (byte) 0x1f, (byte) 0x10, (byte) 0x5a, (byte) 0xd8,
            /* D */     (byte) 0x0a, (byte) 0xc1, (byte) 0x31, (byte) 0x88, (byte) 0xa5, (byte) 0xcd, (byte) 0x7b, (byte) 0xbd, (byte) 0x2d, (byte) 0x74, (byte) 0xd0, (byte) 0x12, (byte) 0xb8, (byte) 0xe5, (byte) 0xb4, (byte) 0xb0,
            /* E */     (byte) 0x89, (byte) 0x69, (byte) 0x97, (byte) 0x4a, (byte) 0x0c, (byte) 0x96, (byte) 0x77, (byte) 0x7e, (byte) 0x65, (byte) 0xb9, (byte) 0xf1, (byte) 0x09, (byte) 0xc5, (byte) 0x6e, (byte) 0xc6, (byte) 0x84,
            /* F */     (byte) 0x18, (byte) 0xf0, (byte) 0x7d, (byte) 0xec, (byte) 0x3a, (byte) 0xdc, (byte) 0x4d, (byte) 0x20, (byte) 0x79, (byte) 0xee, (byte) 0x5f, (byte) 0x3e, (byte) 0xd7, (byte) 0xcb, (byte) 0x39, (byte) 0x48
    };

    /**
     * GM/T 0002-2012 7.3 系统参数 FK
     */
    private static int[] FK = {
            0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
    };

    /**
     * GM/T 0002-2012 7.3 固定参数 CK
     * <p>
     * CKi，(i=0,1,...,31)
     */
    private static int[] CK = {
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    };

    /**
     * 循环左移
     *
     * @param x    要移动的数
     * @param bits 移动位数
     * @return 移动完成的数
     */
    private int rotateLeft(int x, int bits) {
        return (x << bits) | (x >>> (32 - bits));
    }

    /**
     * 轮函数 F
     * <p>
     * GM/T 0002-2012 6.1 轮函数结构
     * <p>
     * rk ∈ (2 ^ 32)
     * <p>
     * F(X0, X1, X2, X3, rk) = X0 ⊕ T(X1 ⊕ X2 ⊕ X3 ⊕ rk)
     *
     * @param x0 输入参数 X0
     * @param x1 输入参数 X1
     * @param x2 输入参数 X2
     * @param x3 输入参数 X3
     * @param rk 轮密钥
     * @return 轮函数结果 字（2^32）
     * @author 权观宇
     * @date 2019-02-24 16:19:56
     */
    public int F(int x0, int x1, int x2, int x3, int rk) {
        // X0 ⊕ T(X1 ⊕ X2 ⊕ X3 ⊕ rk)
        return x0 ^ T(x1 ^ x2 ^ x3 ^ rk);
    }

    /**
     * 合成转置T
     * <p>
     * GM/T 0002-2012 6.2 合成转置T
     * <p>
     * T是一个可逆变换，由非线性变换τ和线性变换L 复合而成，即 T(.) = L(τ(.))
     *
     * @param var 转置参数，X0 ⊕ T(X1 ⊕ X2 ⊕ X3 ⊕ rk)
     * @return 转置字 (2^32)
     */
    private int T(int var) {
        return L(tau(var));
    }

    /**
     * 线性变换L
     * <p>
     * C = L(B) = B⊕(B<<<2)⊕(B<<<10)⊕(B<<<18)⊕(B<<<24)
     *
     * @param b 变换参数
     * @return 变换结果字 (2 ^ 32)
     * @author 权观宇
     * @date 2019-02-24 16:30:10
     */
    private int L(int b) {
        // B⊕(B<<<2)⊕(B<<<10)⊕(B<<<18)⊕(B<<<24)
        return b ^ rotateLeft(b, 2) ^ rotateLeft(b, 10) ^ rotateLeft(b, 18) ^ rotateLeft(b, 24);
    }


    /**
     * 非线性变换τ
     *
     * @param a 变换参数
     * @return 变换结果字 (2 ^ 32)
     * @author 权观宇
     * @date 2019-02-25 12:31:23
     */
    private int tau(int a) {
        int b0 = Sbox[(a >> 24) & 0xFF] & 0xFF;
        int b1 = Sbox[(a >> 16) & 0xFF] & 0xFF;
        int b2 = Sbox[(a >> 8) & 0xFF] & 0xFF;
        int b3 = Sbox[a & 0xFF] & 0xFF;
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }

    /**
     * 加密算法
     * <p>
     * 加密算法由32次迭代运算和1次反序列变换R组成
     *
     * @param x      明文
     * @param mk     密钥
     * @param encryp 是否是加密模式；true - 加密； false - 解密；
     * @return 密文
     */
    private int[] crypto(int[] x, int[] mk, boolean encryp) {

        // 轮运算结果值临时变量
        int xTmp = 0;
        /*
         * 32 次迭代运算：Xi+4 = F(Xi, Xi+1, Xi+2, Xi+3, rki), i = 0,1,...,31
         */
        final int round = 32;
        // 计算每一轮的轮密钥
        int[] rk = getRk(mk, encryp);
        for (int i = 0; i < round; i++) {
            // 运行轮函数得到这一轮的结果值
            xTmp = F(x[0], x[1], x[2], x[3], rk[i]);
//            System.out.printf("rk[%2d] = %08X\tX[%2d] = %08X\n", i, rk[i], i + 4, xTmp);

            /*
             * 左移动，计算下一字
             */
            x[0] = x[1];
            x[1] = x[2];
            x[2] = x[3];
            x[3] = xTmp;
        }
        /*
         * (2)  反序列变换
         *  (Y0, Y1, Y2, Y3) = R(X32, X33, X34, X35) = (X35, X34, X33, X32)
         */
        return R(x);
    }

    /**
     * 线性变换 T'
     * <p>
     * 把T的线性变换L替换为L'
     * <p>
     * L'(tau(B));
     *
     * @param b 变换字
     * @return 变换后的字
     * @author 权观宇
     * @date 2019-2-25 12:23:38
     */
    private int Tba(int b) {
        return Lba(tau(b));
    }

    /**
     * 线性变换L'
     * <p>
     * B⊕(B<<<13)⊕(B<<<23)
     *
     * @param b 待变换字
     * @return 变换结果字
     * @author 权观宇
     * @date 2019-02-25 12:22:52
     */
    private int Lba(int b) {
        // B⊕(B<<<13)⊕(B<<<23)
        return b ^ rotateLeft(b, 13) ^ rotateLeft(b, 23);
    }

    /**
     * 轮密钥生成
     *
     * @param mk     密钥
     * @param encryp 是否是加密模式
     * @return 密钥序列 rk
     * @author 权观宇
     * @date 2019-02-24 18:33:32
     */
    private int[] getRk(int[] mk, boolean encryp) {
        int[] rk = new int[32];
        int[] k = new int[32 + 4];

        /*
         * 7.3 密钥扩展算法 生成 (K0, K1, K2, K3)
         * (K0, K1, K2, K3) = (MK0⊕FK0,MK1⊕FK1,MK2⊕FK2,MK3⊕FK3)
         */
        k[0] = mk[0] ^ FK[0];
        k[1] = mk[1] ^ FK[1];
        k[2] = mk[2] ^ FK[2];
        k[3] = mk[3] ^ FK[3];

        for (int i = 0; i < 32; i++) {
            k[i + 4] = k[i] ^ Tba(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);

            if (encryp) {
                rk[i] = k[i + 4];
            } else {
                /*
                 * 解密轮密钥与加密轮密钥顺序相反
                 * 倒顺排列
                 */
                rk[31 - i] = k[i + 4];
            }
//            System.out.printf("k[%2d] = %08X\n", i, k[i]);
        }
        return rk;
    }


    /**
     * (2) 反序列变换
     * <p>
     * (Y0, Y1, Y2, Y3) = R(X32, X33, X34, X35) = (X35, X34, X33, X32)
     *
     * @param x 序列X
     * @return 反序列
     * @author 权观宇
     * @date 2019-02-24 18:01:23
     */
    private int[] R(int[] x) {
        /*
         * 对称交换 1、4 位
         */
        int tmp = x[0];
        x[0] = x[3];
        x[3] = tmp;
        /*
         * 对称交换 2、3 位
         */
        tmp = x[1];
        x[1] = x[2];
        x[2] = tmp;
        return x;
    }

    /**
     * 运行单次SM4 加密
     *
     * @param plaintext 明文
     * @param key       密钥
     * @return 密文
     */
    public byte[] sm4Enc(byte[] plaintext, byte[] key) {
        if (plaintext == null || plaintext.length != 16) {
            throw new IllegalArgumentException("plaintext illegal it should be 16Byte(128Bit)");
        }
        if (key == null || key.length != 16) {
            throw new IllegalArgumentException("key illegal it should be 16Byte(128Bit)");
        }
        // 设置输入明文(X0, X1, X2, X3)∈(2^32)^4
        int[] x = byteToInt32(plaintext);
        // 设置密钥
        int[] mk = byteToInt32(key);
        // 加密
        int[] y = crypto(x, mk, true);
        // 类型转换
        return int32ToByte(y);
    }

    /**
     * 字节数组转为32位元组
     *
     * @param b 字节数组
     * @return 32bit的元组
     * @author 权观宇
     * @date 2019-02-24 18:51:37
     */
    private static int[] byteToInt32(byte[] b) {
        int[] int32Array = new int[4];
        for (int i = 0; i < 4; i++) {
            int32Array[i] = (b[i * 4 + 3]) & 0xFF |
                    (b[i * 4 + 2] & 0xFF) << 8 |
                    (b[i * 4 + 1] & 0xFF) << 16 |
                    (b[i * 4] & 0xFF) << 24;
        }
        return int32Array;
    }

    /**
     * 2位元组转字节序列
     *
     * @param int32Array 待转32元组
     * @return 对应的字节序列
     * @author 权观宇
     * @date 2019-02-24 19:01:02
     */
    private static byte[] int32ToByte(int[] int32Array) {

        if (int32Array == null || int32Array.length != 4) {
            throw new IllegalArgumentException("int array must be 4 length");
        }
        byte[] res = new byte[16];
        for (int i = 0; i < 4; i++) {
            res[i * 4] = (byte) ((int32Array[i] >> 24) & 0xFF);
            res[i * 4 + 1] = (byte) ((int32Array[i] >> 16) & 0xFF);
            res[i * 4 + 2] = (byte) ((int32Array[i] >> 8) & 0xFF);
            res[i * 4 + 3] = (byte) ((int32Array[i]) & 0xFF);
        }
        return res;
    }
}
