package com.nucypher.crypto.elgamal;

import java.security.PublicKey;
import java.security.SecureRandom;

import org.bouncycastle.jce.spec.ECParameterSpec;

public class ElGamalEncryptor {
	public static byte[] encrypt(PublicKey pk, byte[] message, ECParameterSpec params, SecureRandom random) {
		WrapperElGamalPRE pre = new WrapperElGamalPRE(params, random);
		return pre.encrypt(pk, message);
	}
}
