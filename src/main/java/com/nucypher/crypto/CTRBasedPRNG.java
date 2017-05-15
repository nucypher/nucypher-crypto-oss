package com.nucypher.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

public class CTRBasedPRNG {
	
	private byte[] iv, k;
	private Cipher cipher;
	
	public CTRBasedPRNG(byte[] seed) throws Exception{
		cipher = Cipher.getInstance("AES/CTR/NoPadding");

		int l = cipher.getBlockSize();

	    
	    IvParameterSpec ivSpec = new IvParameterSpec(seed, 0, l);
	    SecretKeySpec key = new SecretKeySpec(seed, l, seed.length - l, "AES");
	    
	    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
	}
	
	public void nextBytes(byte[] out){
		if(out==null || out.length==0){
			throw new IllegalArgumentException();
		} else {
			System.arraycopy(cipher.update(new byte[out.length]), 0, out, 0, out.length);
		}
	}
	
	
	public static void main(String[] args) throws Exception{
		byte[] seed = Hex.decode("0001020304050607080910111213141516171819202122232425262728293031");
		CTRBasedPRNG prng = new CTRBasedPRNG(seed);
		
		byte[] out = new byte[10];
		prng.nextBytes(out);
		System.out.println(Hex.toHexString(out));
		
		out = new byte[3];
		prng.nextBytes(out);
		System.out.println(Hex.toHexString(out));
		
		out = new byte[123];
		prng.nextBytes(out);
		System.out.println(Hex.toHexString(out));
	}
	
}
