package ch.fhnw.kry.crypto.spn;

import java.util.function.Function;

public class SPN {
    private int n;
    private int m;
    private int rounds;
    private SBox box;
    private BitPermutation permutation;

    private int boxMaskTemplate = 0; // used for s-box
    private int keyMaskTemplate = 0; // used to extract key parts

    /**
     * @param n length of blocks
     * @param m number of blocks
     * @param rounds number of rounds
     * @param box S-Box
     * @param permutation Bit permutations
     */
    public SPN(int n, int m, int rounds, SBox box, BitPermutation permutation) {
        this.n = n;
        this.m = m;
        this.rounds = rounds;
        this.box = box;
        this.permutation = permutation;

        preComputeNMask();
        preComputeKeyMask();
    }

    public int encrypt(int plain, int key) {
        // pre-conditions:
        // - plain should contain n*m relevant bits starting from the MSB
        // - key must be of any length which is a multiple of n
        // - size must not exceed int limit (32-bits)

        // 1. init: plain = XOR(plain, K(key, 0))
        var input = nextInput(0, plain, key);

        // 2. range (1, rounds - 1):
        //      2.1: for each part of plain: part = SBox(part)
        //      2.2: for each x: x = BitPerm(x)
        //      2.3: result = XOR(result, K(key, round))
        for (int i = 1; i < rounds; i++) {
            input = sBox(input, box::getReplacement);
            input = permutations(input, permutation::getSwapIndex);
            input = nextInput(i, input, key);
        }

        // 3. final round:
        //      3.1: for each part of plain: part = SBox(part)
        //      3.2: result = XOR(result, K(key, round))
        input = sBox(input, box::getReplacement);
        return nextInput(rounds, input, key);
    }

    public int decrypt(int encrypted, int key) {
        // pre-conditions:
        // - plain should contain n*m relevant bits starting from the MSB
        // - key must be of any length which is a multiple of n
        // - size must not exceed int limit (32-bits)

        // 1. init: input = XOR(encrypted, K'(key, 0))
        //    special case: use K'(k, rounds-i) if i=0 or i=rounds => K'(k, rounds)
        var input = encrypted ^ nextKeyPart(rounds, key);

        // 2. range (1, rounds - 1):
        //      2.1: for each part of plain: part = SBox'(part)
        //      2.2: for each x: x = BitPerm'(x)
        //      2.3: result = XOR(result, permutations(K'(key, rounds-i)))
        for (int i = 1; i < rounds; i++) {
            input = sBox(input, box::getInverseReplacement);
            input = permutations(input, permutation::getSwapIndexInverted);
            input = input ^ permutations(nextKeyPart(rounds - i, key), permutation::getSwapIndexInverted);
        }

        // 3. final round:
        //      3.1: for each part of plain: part = SBox'(part)
        //      3.2: result = XOR(result, K'(key, 0))
        //           special case: use K'(k, rounds-i) if i=0 or i=rounds => K'(k, 0)
        input = sBox(input, box::getInverseReplacement);
        return input ^ nextKeyPart(0, key);
    }

    private int sBox(int value, Function<Integer, Integer> replacementFunc) {
        var boxMask = this.boxMaskTemplate;

        // computations using adjusted mask:
        // input: 0001_0010_0100_1000, n=4, m=4
        // 1111_0000_0000_0000, n=4, i=0 => 0001_0000_0000_0000
        // 0000_1111_0000_0000, n=4, i=1 => 0000_0010_0000_0000
        // 0000_0000_1111_0000, n=4, i=2 => 0000_0000_0100_0000
        // 0000_0000_0000_1111, n=4, i=3 => 0000_0000_0000_1000
        var result = 0;
        for (int partStartIndex = 0; partStartIndex < m; partStartIndex++) {
            // replace (i, i+n] bits of input using SBox definition
            var partial = (value & boxMask) >>> (32 - (n * (partStartIndex + 1)));

            var replacement = replacementFunc.apply(partial);
            result |= (replacement << (32 - n*(partStartIndex+1)));
            // move the mask by n bits for next iteration
            boxMask >>>= n;
        }

        return result;
    }

    private int permutations(int value, Function<Integer, Integer> permutationFunc) {
        var result = 0;
        for (int bitIndex = 0; bitIndex < n*m; bitIndex++) {
            var swapIndex = permutationFunc.apply(bitIndex);
            // extract the bit-value as a single bit (LSB)
            var newBitValue = (value >>> (31 - swapIndex)) & 1;
            // move bit-value to position which needs to be replaced
            result |= (newBitValue << (31 - bitIndex));
        }
        return result;
    }

    private int nextInput(int round, int x, int key) {
        // x = XOR(x, K(k, round))
        return x ^ nextKeyPart(round, key);
    }

    private int nextKeyPart(int round, int key) {
        var keyMask = this.keyMaskTemplate;

        // extract relevant bits of the key
        // by a computed mask which has length n*m
        // and align the extracted bits so that the
        // MSB is the start of the returned value
        // and the extracted value
        keyMask >>>= n*round;
        return (key & keyMask) << n*round;
    }


    private void preComputeNMask() {
        for (int i = 0; i < n; i++) {
            boxMaskTemplate |= (1 << (32 - n + i));
        }
    }

    private void preComputeKeyMask() {
        for (int i = 0; i < n*m; i++) {
            keyMaskTemplate |= (1 << (32 - n*m + i));
        }
    }
}
