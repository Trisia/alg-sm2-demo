package edu.hznu.crypto.algsm2demo;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class CertParser {
    public static void main(String[] args) throws IOException {
        Path path = Paths.get("C:\\Users\\Cliven\\Desktop\\cert.hex");
        byte[] bytes = Files.readAllBytes(path);
        byte[] record = Hex.decode(bytes);
        System.out.println(record.length);
        ByteArrayInputStream bin = new ByteArrayInputStream(record);
        do {
            byte[] buff = new byte[5];
            bin.read(buff);
            int len = (buff[3] & 0xFF) << 8 | (buff[4] & 0xFF);
            System.out.printf("Type: %d, Version %d.%d, Length: %d\n", buff[0], buff[1], buff[2], len);
            byte[] fragment = new byte[len];
            bin.read(fragment);
            handshake(fragment);
        } while (bin.available() > 0);
    }

    public static void handshake(byte[] bin) throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(bin);
        byte[] buff = new byte[4];
        in.read(buff);
        int len = (buff[1] & 0xFF) << 16 |
                (buff[2] & 0xFF) << 8 |
                (buff[3] & 0xFF);
        byte type = buff[0];
        System.out.printf("\tHandshake Type: %d, Length: %d\n", type, len);
        buff = new byte[len];
        in.read(buff);
        if (type == 11) {
            cert(buff);
        }
    }

    private static void cert(byte[] bin) throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(bin);
        byte[] buff = new byte[3];
        in.read(buff);
        int len = (buff[0] & 0xFF) << 16 |
                (buff[1] & 0xFF) << 8 |
                (buff[2] & 0xFF);
        System.out.printf("\t\tCertSize: %d Byte\n", len);
        buff = new byte[len];
        in.read(buff);
        ByteArrayInputStream certIn = new ByteArrayInputStream(buff);
        int cnt = 0;
        do {
            cnt++;
            buff = new byte[3];
            certIn.read(buff);
            len = (buff[0] & 0xFF) << 16 |
                    (buff[1] & 0xFF) << 8 |
                    (buff[2] & 0xFF);
            buff = new byte[len];
            certIn.read(buff);
            for (int i = 0; i < len; i++) {
                System.out.printf("%02X", buff[i]);
            }
            System.out.println();
            Path p = Paths.get("target/Cert" + cnt+".cer");
            Files.write(p,  Base64.encode(buff));
        } while (certIn.available() > 0);
    }


}
