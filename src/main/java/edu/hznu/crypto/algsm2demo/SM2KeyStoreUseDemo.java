package edu.hznu.crypto.algsm2demo;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Scanner;

/**
 * KeyStore 使用Demo
 *
 * @author 权观宇
 * @since 2019-11-27 10:11:17
 */
public class SM2KeyStoreUseDemo {
    /**
     * 日期格式化
     */
    private static final SimpleDateFormat SDF;

    static {
        Security.addProvider(new BouncyCastleProvider());
        SDF = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    }

    /**
     * 读入字符串
     *
     * @param hit 提示文字
     * @return 读取到的输入参数
     */
    private static String scanIn(String hit) {
        Scanner sc = new Scanner(System.in);
        System.out.println(hit);
        System.out.print("> ");
        String ans = sc.nextLine().trim();
        System.out.println();
        return ans;
    }

    public static void main(String[] args) throws Exception {
        System.out.println();
        System.out.println("|             Go Go Certificate!             |");
        System.out.println();

        String keyPath = scanIn("请输入P12存储路径:");
        if (keyPath.trim().length() == 0) {
            System.err.println("P12文件路径为空");
            return;
        }
        File file = new File(keyPath);
        if (!file.exists()) {
            System.err.println("P12文件不存在: " + keyPath);
            return;
        }

        String outPath = scanIn("请输入签发证书存储路径:");
        if (outPath.trim().length() == 0) {
            System.err.println("证书生成路径为空");
            return;
        }
        File out = new File(outPath);

        /*
         * 注意此处可能会发生 JCE cannot authenticate the provider BC 的错误
         *
         * 为解决这个问题需要在 在jre的 /lib/security/java.security 文件中加入
         *
         * security.provider.11=org.bouncycastle.jce.provider.BouncyCastleProvider
         *
         * （例如： C:\Program Files\Java\jre1.8.0_231\lib\security）
         *
         * 然后将对应版本的BC jar包移动到jre的 /lib/ext 中 （bcprov-jdk15on-1.64.jar）
         *
         * （例如： C:\Program Files\Java\jre1.8.0_231\lib\ext）
         *
         * 再次运行就可以解决问题，如果有多个jre请确认当前使用的是哪一个。
         */
        // 1. 载入P12得到证书和私钥
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");
        try (FileInputStream fIn = new FileInputStream(keyPath);
             FileWriter fw = new FileWriter(out)) {

            char[] pwd = scanIn("输入P12(KeyStore)密码:").toCharArray();
            store.load(fIn, pwd);
            // 2. 取得CA根证书
            Certificate root = store.getCertificateChain("private")[0];
            // 3. 取得CA根证书的私钥
            PrivateKey privateKey = (PrivateKey) store.getKey("private", pwd);

            X509CertificateHolder holder = new X509CertificateHolder(root.getEncoded());
            System.out.println("CA证书有效期为 "
                    + SDF.format(holder.getNotBefore())
                    + " 至 "
                    + SDF.format(holder.getNotAfter()));
            System.out.println();
            System.out.println("注：签发证书默认有效时长为 3小时");
            System.out.println();

            String p10 = scanIn("请输入P10:");

            // 4. 签发证书
            X509Certificate userCert = SM2SubCertGenerateDemo.issue(p10, root, privateKey);
            // 5. 保存到本地
            fw.write(Base64.toBase64String(userCert.getEncoded()));
            System.out.println();
        }

        System.out.println();
        System.out.println(">>> 证书签发成功，证书存储路径: \n\n\t" + out.getAbsolutePath());
        System.out.println();
    }
}
