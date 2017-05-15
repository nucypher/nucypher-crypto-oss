package com.nucypher.crypto.elgamal;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import com.nucypher.crypto.CTRBasedPRNG;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;

public class ElGamalKeypairGenerator {
	public static KeyPair generateKeypair(ECParameterSpec params, SecureRandom random) {
		KeyPairGenerator kpg = null;
		try {
			kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
			kpg.initialize(params, random);
			return kpg.generateKeyPair();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static KeyPair generateKeypair(ECParameterSpec params, byte[] seed) throws Exception {
		BigInteger n = params.getN();
		
		CTRBasedPRNG prng = new CTRBasedPRNG(seed);
		
		BigInteger k;

		do {
			k = WrapperElGamalPRE.getBigIntegerFromPRNG(n.bitLength(), prng);
		} while (k.equals(ECConstants.ZERO) || (k.compareTo(n) >= 0));

		ECPrivateKeySpec skSpec = new ECPrivateKeySpec(k, params);
		
		ECPoint pkPoint = params.getG().multiply(k);
		
		ECPublicKeySpec pkSpec = new ECPublicKeySpec(pkPoint, params);
		
		KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
		PrivateKey privKey = keyFactory.generatePrivate(skSpec);
		PublicKey pubKey = keyFactory.generatePublic(pkSpec);

		return new KeyPair(pubKey, privKey);

	}
}
