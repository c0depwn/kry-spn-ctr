package ch.fhnw.kry.crypto.spn;

import java.util.Arrays;
import java.util.Map;

public class BitPermutation {
    private final int[] indexMapping;
    private final int[] indexMappingInverted;

    public BitPermutation(int[] indexMapping) {
        this.indexMapping = indexMapping;
        this.indexMappingInverted = new int[indexMapping.length];

        // pre-compute inversion of bit permutation table
        for (int i = 0; i < this.indexMapping.length; i++) {
            this.indexMappingInverted[this.indexMapping[i]] = i;
        }
    }

    public int getSwapIndex(int indexOfBit) {
        return indexMapping[indexOfBit];
    }

    public int getSwapIndexInverted(int indexOfBit) {
        return indexMappingInverted[indexOfBit];
    }
}
