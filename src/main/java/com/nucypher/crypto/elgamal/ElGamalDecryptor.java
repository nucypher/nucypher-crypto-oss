package com.nucypher.crypto.elgamal;

import java.security.PrivateKey;

import org.bouncycastle.jce.spec.ECParameterSpec;

public class ElGamalDecryptor {
	public static byte[] decrypt(PrivateKey sk, byte[] c, ECParameterSpec params) {
		WrapperElGamalPRE pre = new WrapperElGamalPRE(params, null);
		return pre.decrypt(sk, c);
	}
}
