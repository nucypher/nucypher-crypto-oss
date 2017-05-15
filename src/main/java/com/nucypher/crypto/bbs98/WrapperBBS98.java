package com.nucypher.crypto.bbs98;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import com.nucypher.crypto.CTRBasedPRNG;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class WrapperBBS98 {

	private ECParameterSpec params;
	private SecureRandom random;

	public WrapperBBS98(ECParameterSpec params, SecureRandom random) {
		// TODO: check arguments
		this.params = params;
		this.random = random;
	}
	
	public KeyPair keygen() throws InvalidAlgorithmParameterException{
		return this.keygen(random);
	}
	
//	public KeyPair keygen(byte[] input, byte[] salt) throws InvalidAlgorithmParameterException{
//		Digest hash = new SHA256Digest();
//        byte[] info = new byte[0];
//        int l = 440 / 8; // NIST SP800-90A suggests 440 bits for SHA1 seed
//        byte[] okm = new byte[l];
//
//        HKDFParameters params = new HKDFParameters(input, salt, info);
//
//        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(hash);
//        hkdf.init(params);
//        hkdf.generateBytes(okm, 0, l);
//        
//        // TODO: SP800SecureRandomBuilder
//        SecureRandom prng;
//		try {
//			prng = SecureRandom.getInstance("SHA1PRNG");
//		} catch (NoSuchAlgorithmException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//			prng = new SecureRandom();
//		}
//        prng.setSeed(okm);
//        
//		return this.keygen(prng);
//	}
	
	public KeyPair keygen(byte[] seed) throws Exception {
		BigInteger n = this.params.getN();
		
		CTRBasedPRNG prng = new CTRBasedPRNG(seed);
		
		BigInteger k;

		do {
			k = getBigIntegerFromPRNG(n.bitLength(), prng);
		} while (k.equals(ECConstants.ZERO) || (k.compareTo(n) >= 0));

		ECPrivateKeySpec skSpec = new ECPrivateKeySpec(k, this.params);
		
		ECPoint pkPoint = this.params.getG().multiply(k);
		
		ECPublicKeySpec pkSpec = new ECPublicKeySpec(pkPoint, this.params);
		
		KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
		PrivateKey privKey = keyFactory.generatePrivate(skSpec);
		PublicKey pubKey = keyFactory.generatePublic(pkSpec);

		return new KeyPair(pubKey, privKey);

	}
	
	public static BigInteger getBigIntegerFromPRNG(int nBits, CTRBasedPRNG prng) {
		int numBytes = (int)(((long)nBits+7)/8);
		byte[] randomBits = new byte[numBytes];
		
		prng.nextBytes(randomBits);
		int excessBits = 8*numBytes - nBits;
		randomBits[0] &= (1 << (8-excessBits)) - 1;
		
		return new BigInteger(1, randomBits);
	}
	
	public KeyPair keygen(SecureRandom r) throws InvalidAlgorithmParameterException{
		KeyPairGenerator kpg = null;
		try {
			kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		kpg.initialize(params, r);
		return kpg.generateKeyPair();
	}
	
	public BigInteger rekeygen(PrivateKey sk_a, PrivateKey sk_b){
		BigInteger inv_sk_a = ((ECPrivateKey) sk_a).getD().modInverse(this.params.getN());
		BigInteger rk = ((ECPrivateKey) sk_b).getD().multiply(inv_sk_a).mod(this.params.getN());
		return rk;
	}

	public byte[] encrypt(PublicKey pk, byte[] message) {

		ECPoint m = encodeToECPoint(params, message, random);

		ECPoint[] c = BBS98BouncyCastle.encrypt(params, ((ECPublicKey) pk).getQ(), m, random);

		ECPoint c0 = c[0].normalize();
		System.out.printf("x: %s, y: %s\n", c0.getAffineXCoord(), c0.getAffineYCoord());
		return encodeTuple(c);
	}

	public byte[] decrypt(PrivateKey sk, byte[] ciphertext) {
		ECPoint[] c = decodeTuple(ciphertext);

		ECPoint mPoint = BBS98BouncyCastle.decrypt(params, ((ECPrivateKey) sk).getD(), c);

		return decodeFromECPoint(this.params, mPoint);
	}

	public byte[] reencrypt(BigInteger rk, byte[] ciphertext) {

		ECPoint[] c = decodeTuple(ciphertext);

		ECPoint[] c_prime = BBS98BouncyCastle.reencrypt(params, rk, c);

		return encodeTuple(c_prime);
	}

	// TODO: Encoding to elliptic curve points is not implemented in BC
	public static ECPoint encodeToECPoint(ECParameterSpec ps, byte[] message, SecureRandom sr) {
		// Method based on Section 2.4 of https://eprint.iacr.org/2013/373.pdf

//		System.out.println("Encoding: " + BBS98BouncyCastle.bytesToHex(message));
		int lBits = ps.getN().bitLength() / 2;
//		System.out.println("N = " + ps.getN());
//		System.out.println("lbits: " + lBits);

		if (message.length * 8 > lBits) {
			throw new IllegalArgumentException("Message too large to be encoded");
		}

		BigInteger mask = BigInteger.ZERO.flipBit(lBits).subtract(BigInteger.ONE);
		BigInteger m = new BigInteger(1, message);

		ECFieldElement a = ps.getCurve().getA();
		ECFieldElement b = ps.getCurve().getB();

		BigInteger r;
		ECFieldElement x = null, y = null;
		do {
			r = BBS98BouncyCastle.getRandom(sr, ps.getN());
			r = r.andNot(mask).or(m);

			if (!ps.getCurve().isValidFieldElement(r)) {
				continue;
			}

			x = ps.getCurve().fromBigInteger(r);

			// y^2 = x^3 + ax + b = (x^2+a)x +b
			ECFieldElement y2 = x.square().add(a).multiply(x).add(b);
			y = y2.sqrt();

		} while (y == null);
		return ps.getCurve().createPoint(x.toBigInteger(), y.toBigInteger());

	}

	// TODO: Encoding to elliptic curve points is not implemented in BC
	public static byte[] decodeFromECPoint(ECParameterSpec ps, ECPoint point) {
		// Method based on Section 2.4 of https://eprint.iacr.org/2013/373.pdf

		int lBits = ps.getN().bitLength() / 2;

		byte[] bs = new byte[lBits / 8];

		byte[] xbytes = point.normalize().getAffineXCoord().toBigInteger().toByteArray();

		System.arraycopy(xbytes, xbytes.length - bs.length, bs, 0, bs.length);
//		System.out.println("Decoded: " + BBS98BouncyCastle.bytesToHex(bs));
		return bs;
	}

	public ECPoint[] decodeTuple(byte[] tuple) {
//		if (tuple.length != 2 * COMPRESSED_ECPOINT_LENGTH) {
//			throw new IllegalArgumentException("Encoded tuple does not match expected size");
//		}
//
//		byte[] p1Bytes = new byte[COMPRESSED_ECPOINT_LENGTH];
//		byte[] p2Bytes = new byte[COMPRESSED_ECPOINT_LENGTH];

		int component_length = tuple.length / 2;

		byte[] p1Bytes = new byte[component_length];
		byte[] p2Bytes = new byte[component_length];

		
		System.arraycopy(tuple, 0, p1Bytes, 0, component_length);
		System.arraycopy(tuple, component_length, p2Bytes, 0, component_length);

		ECPoint p1 = params.getCurve().decodePoint(p1Bytes);
		ECPoint p2 = params.getCurve().decodePoint(p2Bytes);

		return new ECPoint[] { p1, p2 };
	}

	public byte[] encodeTuple(ECPoint[] tuple) {

		byte[] p1Bytes = tuple[0].getEncoded(true);
		byte[] p2Bytes = tuple[1].getEncoded(true);
		
		int point_length = p1Bytes.length;

		byte[] encoded = new byte[2 * point_length];

		System.arraycopy(p1Bytes, 0, encoded, 0, point_length);
		System.arraycopy(p2Bytes, 0, encoded, point_length, point_length);
		try {
			Hex.encode(tuple[0].getEncoded(true), System.out);
			System.out.println();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return encoded;
	}

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		SecureRandom sr = new SecureRandom(); // SecureRandom is thread-safe

		Security.addProvider(new BouncyCastleProvider());

		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-256");
		
		

		for (int i = 0; i < 10; i++) {
			byte[] message = new byte[16];
			sr.nextBytes(message);

			// ECPoint point = encodeToECPoint(ecSpec, message, sr);
			// System.out.println(point);
			// byte[] res = decodeFromECPoint(ecSpec, point);

			BigInteger n = ecSpec.getN();

			KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");

			kpg.initialize(ecSpec, new SecureRandom());
			KeyPair pair = kpg.generateKeyPair();

			PublicKey pki = pair.getPublic();
			PrivateKey xi = pair.getPrivate();

			WrapperBBS98 pre = new WrapperBBS98(ecSpec, sr);

			byte[] c = pre.encrypt(pki, message);
			

			byte[] m2 = pre.decrypt(xi, c);
//			System.out.println("m2 = " + BBS98BouncyCastle.bytesToHex(m2));

			if (!Arrays.areEqual(m2, message)) {
				System.out.println("Error 1!");
			}

			byte[] seed = Hex.decode("0001020304050607080910111213141516171819202122232425262728293031");
			
			pair = pre.keygen(seed);
			PublicKey pkj = pair.getPublic();
			PrivateKey xj = pair.getPrivate();
			
			//
			// // RKG & REENC
			//
			BigInteger rk = pre.rekeygen(xi, xj);
			System.out.printf("%x\n", rk);
			
			
			byte[] c_j = pre.reencrypt(rk, c);

			byte[] m3 = pre.decrypt(xj, c_j);
//			System.out.println("m3 = " + BBS98BouncyCastle.bytesToHex(m2));

			if (!Arrays.areEqual(m3, message)) {
				System.out.println("Error 2!");
			}
			
		}
		System.out.println("End");
		byte[] seed = Hex.decode("0001020304050607080910111213141516171819202122232425262728293031");
		WrapperBBS98 pre = new WrapperBBS98(ecSpec, sr);
		long t = System.nanoTime();
		for (int i = 0; i < 1000; i++) {
			seed[0] = (byte) (seed [0] ^ i);
			pre.keygen(seed);
		}
		System.out.println((System.nanoTime()-t)/(1000.0 * 1000000) + " ms per keygen");
	}

	/**
	 * Get encrypted message length. Available only for P-256 and P-521 curves
	 *
	 * @param ecSpec {@link ECParameterSpec}
	 * @return message length
	 */
	public static int getMessageLength(ECParameterSpec ecSpec) {
		switch(ecSpec.getN().bitLength()) {
			case 256: return 16;
			case 521: return 32;
			//TODO maybe change to calculating
			default: throw new IllegalArgumentException("Available only for P-256 and P-521 curves");
		}
	}

}
