package com.nucypher.crypto.bbs98;

import java.math.BigInteger;

import javax.security.auth.DestroyFailedException;

import com.nucypher.crypto.interfaces.ReEncryptionKey;

public class BBS98ReEncryptionKey implements ReEncryptionKey {

	/**
	 * 
	 */
	private static final long serialVersionUID = -1881528428226550424L;
	private BigInteger n, rk;
	
	public BBS98ReEncryptionKey(BigInteger rk, BigInteger n){
		this.rk = rk;
		this.n = n;
	}
	
	@Override
	public String getAlgorithm() {
		return BBS98BouncyCastle.ALGORITHM_NAME;
	}

	@Override
	public String getFormat() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] getEncoded() {
		return rk.toByteArray();
	}
	
	public BBS98ReEncryptionKey getTransitiveKey(BBS98ReEncryptionKey rk_prime){
		if(n!=rk_prime.n){
			throw new IllegalArgumentException();
		}
		return new BBS98ReEncryptionKey(rk.multiply(rk_prime.rk).mod(n), n);
	}

	@Override
	public void destroy() throws DestroyFailedException {
        throw new DestroyFailedException();
    }

    @Override
	public boolean isDestroyed() {
        return false;
    }
}
