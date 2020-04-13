package edu.hznu.crypto.algsm2demo;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * SM2 密钥反序列化Demo
 *
 * {@link org.bouncycastle.jcajce.provider.test.GeneralKeyTest#testSM2}
 *
 * @author 权观宇
 * @since 2020-04-13 21:43:02
 */
public class SM2KeyPairInjectDemo {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        final BouncyCastleProvider bc = new BouncyCastleProvider();

        /*
        >> 公钥BASE64: MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAESic24soUECzuSh2aYH0e+hQYh+/I01NmfjOnm5mwyUEYQvNCPTzn3BlNyufgMV+DWLUKV+2h0+PVel9jYTfG8Q==
        >> 私钥BASE64: MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg0dYU+I6IdiSe8bvWlsHuWfsjSn3XFZqOGWO3K1814O6gCgYIKoEcz1UBgi2hRANCAARKJzbiyhQQLO5KHZpgfR76FBiH78jTU2Z+M6ebmbDJQRhC80I9POfcGU3K5+AxX4NYtQpX7aHT49V6X2NhN8bx
        signature:
        3045022100ff9a872f21e47d4fba8f37b48a62cc2e6fdde843a40cbc96242536afc10a395e02203bbab982d1bb6a7ee5f5f6b34cd887c255ae4dcc14dd87ecae2e0392611b7a8c
         */
        byte[] encPub = Base64.decode("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAESic24soUECzuSh2aYH0e+hQYh+/I01NmfjOnm5mwyUEYQvNCPTzn3BlNyufgMV+DWLUKV+2h0+PVel9jYTfG8Q==");
        byte[] encPriv = Base64.decode("MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg0dYU+I6IdiSe8bvWlsHuWfsjSn3XFZqOGWO3K1814O6gCgYIKoEcz1UBgi2hRANCAARKJzbiyhQQLO5KHZpgfR76FBiH78jTU2Z+M6ebmbDJQRhC80I9POfcGU3K5+AxX4NYtQpX7aHT49V6X2NhN8bx");
        byte[] plainText = "你好".getBytes(StandardCharsets.UTF_8);

        KeyFactory keyFact = KeyFactory.getInstance("EC", bc);
        // 根据采用的编码结构反序列化公私钥
        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));


        Signature signature = Signature.getInstance("SM3withSm2", bc);
        signature.initVerify(pub);
        signature.update(plainText);
        // 验证签名值
        boolean res = signature.verify(Hex.decode("3045022100ff9a872f21e47d4fba8f37b48a62cc2e6fdde843a40cbc96242536afc10a395e02203bbab982d1bb6a7ee5f5f6b34cd887c255ae4dcc14dd87ecae2e0392611b7a8c"));
        System.out.println(">> 验证结果:" + res);
    }
}
