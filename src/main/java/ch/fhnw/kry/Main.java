package ch.fhnw.kry;

import ch.fhnw.kry.crypto.mode.CTR;
import ch.fhnw.kry.crypto.spn.BitPermutation;
import ch.fhnw.kry.crypto.spn.SBox;
import ch.fhnw.kry.crypto.spn.SPN;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

public class Main {
    public static void main(String[] args) {
        // TODO: make parameters configurable via CLI

        var sbox = new SBox(new int[]{0xe,0x4,0xd,0x1,0x2,0xf,0xb,0x8,0x3,0xa,0x6,0xc,0x5,0x9,0x0,0x7});
        var perm = new BitPermutation(new int[]{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15});
        var spn = new SPN(4, 4, 4, sbox, perm);

        int key = 0b0011_1010_1001_0100_1101_0110_0011_1111;

        var ctr = new CTR(spn, 16);
        try (
                var input = new FileInputStream("chiffre.txt");
                var output = new FileOutputStream("decrypted.txt");
        ) {
            ctr.decrypt(input, output, key);
        } catch (IOException e) {
            System.out.println("error decrypting: " + e);
        }
    }

    public static String intBits(int v) {
        return String.format("%32s", Integer.toBinaryString(v)).replace(' ', '0');
    }

    public static String intBits(int v, int length) {
        return String.format("%32s", Integer.toBinaryString(v)).replace(' ', '0').substring(0, length);
    }
}