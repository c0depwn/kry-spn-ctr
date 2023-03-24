package ch.fhnw.kry.crypto.spn;

import java.util.HashMap;
import java.util.Map;

public class SBox {
    private final int[] box;
    private final int[] inverted;

    public SBox(int[] box) {
        this.box = box;
        this.inverted = new int[this.box.length];
        // pre-compute inversion of box
        for (int i = 0; i < this.box.length; i++) {
            this.inverted[this.box[i]] = i;
        }
    }

    public int getReplacement(int value) {
        return box[value];
    }

    public int getInverseReplacement(int value) {
        return inverted[value];
    }

}
