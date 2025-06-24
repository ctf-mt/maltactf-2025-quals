pragma circom 2.1.6;

include "circomlib/mimc.circom";
include "circomlib/bitify.circom";


template CalculateMerkleRoot(DEPTH) {
    signal input leaf;
    signal input siblings[DEPTH][254];
    signal input selectors[DEPTH];
    signal output root;
    var currentHash = leaf;
    for (var i = 0; i < DEPTH; i++) {
        0 === selectors[i] * (1 - selectors[i]);
        var sibling = Bits2Num_strict()(siblings[i]);
        var left = (currentHash - sibling) * selectors[i] + sibling;
        var right = (sibling - currentHash) * selectors[i] + currentHash;
        currentHash = MultiMiMC7(2, 91)([left,right], 1);
    }
    
    root <== currentHash;
}


component main = CalculateMerkleRoot(2);
