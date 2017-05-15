package com.nucypher.crypto.bbs98;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;

/**
 *
 * @author cygnusv
 */
public class BBS98BouncyCastle {
	
	public static final String ALGORITHM_NAME = "BBS98";

	public static ECPoint[] encrypt(ECParameterSpec ecSpec, ECPoint pk, ECPoint m, SecureRandom sr) {
		ECPoint g = ecSpec.getG();
		BigInteger n = ecSpec.getN();

		BigInteger r = getRandom(sr, n);

		ECPoint g_r = g.multiply(r);

		ECPoint m_g_r = g_r.add(m);
		ECPoint pk_r = pk.multiply(r);

		return new ECPoint[] { pk_r, m_g_r };
	}

	public static ECPoint decrypt(ECParameterSpec ecSpec, BigInteger sk, ECPoint[] c) {
		if (c.length != 2) {
			throw new IllegalArgumentException("Ciphertext must be a tuple of 2 elements");
		}

		BigInteger n = ecSpec.getN();

		ECPoint g_r = c[0].multiply(sk.modInverse(n)).negate();
		ECPoint m = c[1].add(g_r);

		return m;
	}

	public static ECPoint[] reencrypt(ECParameterSpec ecSpec, BigInteger rk, ECPoint[] c) {
		if (c.length != 2) {
			throw new IllegalArgumentException("Ciphertext must be a tuple of 2 elements");
		}

		ECPoint c0_prime = c[0].multiply(rk);

		return new ECPoint[] { c0_prime, c[1] };
	}

	public static void main(String[] args) throws Exception {
		
		SecureRandom sr = new SecureRandom(); // SecureRandom is thread-safe

		Security.addProvider(new BouncyCastleProvider());

		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-256");
		BigInteger n = ecSpec.getN();

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");

		kpg.initialize(ecSpec, new SecureRandom());
		KeyPair pair = kpg.generateKeyPair();

		ECPoint pki = ((ECPublicKey) pair.getPublic()).getQ();
		BigInteger xi = ((ECPrivateKey) pair.getPrivate()).getD();

		// BigInteger xi = getRandom(n);
		System.out.println("xi = " + xi);
		BigInteger xj = getRandom(sr, n);
		System.out.println("xj = " + xj);

		ECPoint g = ecSpec.getG();
		encoded(g);

		// ECPoint pki = g.multiply(xi);
		System.out.println("pki = " + pki);
		encoded(pki);
		ECPoint pkj = g.multiply(xj);
		System.out.println("pkj = " + pkj);
		encoded(pkj);

		ECPoint m = g.multiply(getRandom(sr, n));
		System.out.println("m = " + m);
		encoded(m);

		ECPoint[] c = encrypt(ecSpec, pki, m, sr);

		ECPoint m2 = decrypt(ecSpec, xi, c);
		System.out.println("m2 = " + m2);
		encoded(m2);

		if (!m2.equals(m)) {
			System.out.println("Error 1!");
		} else {
			System.out.println("m == m2? " + m2.equals(m));
		}

		// RKG & REENC

		BigInteger invxi = xi.modInverse(n);
		BigInteger rk = xj.multiply(invxi).mod(n);

		ECPoint[] c_j = reencrypt(ecSpec, rk, c);

		ECPoint m3 = decrypt(ecSpec, xj, c_j);
		System.out.println("m3 = " + m3);
		if (!m3.equals(m))
			System.out.println("Error 2!");

	}

	public static BigInteger getRandom(SecureRandom sr, BigInteger n) {
		int nBitLength = n.bitLength();
		BigInteger k = new BigInteger(nBitLength, sr);

		while (k.equals(ECConstants.ZERO) || (k.compareTo(n) >= 0)) {
			k = new BigInteger(nBitLength, sr);
		}

		return k;
	}

	public static void encoded(ECPoint p) {
		boolean compression = false;
		byte[] bs = p.getEncoded(compression);
		System.out.println(" --> " + bs.length + " Bytes (uncompressed) : " + bytesToHex(bs));
		compression = true;
		bs = p.getEncoded(compression);
		System.out.println(" --> " + bs.length + " Bytes (compressed) :   " + bytesToHex(bs));
	}

	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

}
