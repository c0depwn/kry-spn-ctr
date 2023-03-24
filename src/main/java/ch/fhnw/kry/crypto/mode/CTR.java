package ch.fhnw.kry.crypto.mode;

import ch.fhnw.kry.crypto.spn.SPN;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class CTR {
    private final SPN spn;
    private final int l;

    public CTR(SPN spn, int blockBitLength) {
        this.spn = spn;
        this.l = blockBitLength;
    }

    public void encrypt(InputStream source, OutputStream target, int key) throws IOException {
        try(
                var reader = new BufferedReader(new InputStreamReader(source));
                var writer = new BufferedWriter(new OutputStreamWriter(target))
        ) {
            // TODO: implement, (optional as of exercise)
        }
    }
    public void decrypt(InputStream source, OutputStream target, int key) throws IOException {
        try(
                var reader = new BufferedReader(new InputStreamReader(source));
                var writer = new BufferedWriter(new OutputStreamWriter(target))
        ) {
            // read l characters which are to be interpreted as a raw bit-string
            var charBuf = new char[l];

            // extract y-1
            var n = reader.read(charBuf);
            var randInitValue = Integer.parseUnsignedInt(new String(charBuf), 2);

            var i = -1;
            n = reader.read(charBuf);

            while (n != -1) {
                i++;

                // store the raw bit string within an integer in an unsigned fashion
                // make sure that the MSB of the bit-string is at the MSB of the int
                var bits = decodeBitString(l, new String(charBuf));

                // y-1 + i
                var incremented = randInitValue + i;
                // ((y-1 + i) mod 2^l): ensure y-1 + i never exceeds 2^l
                var mod = incremented % (1<<l);
                // adjust to align to MSB for encryption algo
                var input = mod << (32 - l);
                // xi = E(((y-1) + i) %  2^l, k) XOR yi
                var decryptedPart = spn.encrypt(input, key) ^ bits;

                // convert the integer with the decrypted bits to an ascii byte array
                // and write it to the output
                var bytes = intToASCIIBytes(decryptedPart);
                var chars = new String(bytes, StandardCharsets.US_ASCII);
                writer.write(chars);

                // read next value
                n = reader.read(charBuf);
            }
        }
    }

    private int decodeBitString(int length, String bits) {
        var bitsIntValue = Integer.parseUnsignedInt(bits, 2);
        if (length == 32) return bitsIntValue;
        bitsIntValue <<= (32 - length);
        return bitsIntValue;
    }

    private byte[] intToASCIIBytes(int value) {
        var numOfChars = l / 8;
        var bytes = new byte[numOfChars];
        for (int i = 0; i < numOfChars; i++) {
            var asciiValue =  (byte)(value >>> (8 * (3 - i)));

            // detect end of input since ASCII only has 7 bits which can be set
            // => if the MSB is set we are done
            if ((asciiValue & (byte)(1<<7)) < 0) return Arrays.copyOfRange(bytes, 0, i);

            bytes[i] = (byte)(value >>> (8 * (3 - i)));
        }
        return bytes;
    }
}
