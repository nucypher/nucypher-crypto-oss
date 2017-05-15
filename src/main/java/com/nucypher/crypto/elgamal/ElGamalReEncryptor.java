package com.nucypher.crypto.elgamal;

import java.math.BigInteger;

import org.bouncycastle.jce.spec.ECParameterSpec;

public class ElGamalReEncryptor {
	public static byte[] reencrypt(BigInteger rk, byte[] c, ECParameterSpec params) {
		WrapperElGamalPRE pre = new WrapperElGamalPRE(params, null);
		return pre.reencrypt(rk, c);
	}
}
