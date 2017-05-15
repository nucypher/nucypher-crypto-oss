package com.nucypher.crypto.elgamal;

import java.math.BigInteger;
import java.security.PrivateKey;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class ElGamalReEncryptionKeyGenerator {
	public static BigInteger generateReEncryptionKey(PrivateKey _skA, PrivateKey _skB, ECParameterSpec params) {
			ECPrivateKey skA = (ECPrivateKey) _skA;
			ECPrivateKey skB = (ECPrivateKey) _skB;
			
			BigInteger n = params.getN();
			BigInteger inv_sk_b = skB.getD().modInverse(n);
			BigInteger rk = skA.getD().multiply(inv_sk_b).mod(n);
			
			return rk;
		}
}
