package com.nucypher.crypto.bbs98;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import com.nucypher.crypto.interfaces.ReEncryptionKey;
import com.nucypher.crypto.interfaces.ReEncryptionKeyGenerator;
import org.bouncycastle.jce.interfaces.ECPrivateKey;

public class BBS98ReEncryptionKeyGenerator extends ReEncryptionKeyGenerator {

	BBS98ReKeyGenParameterSpec params;
	
	@Override
	public void initialize(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
		algorithm = BBS98BouncyCastle.ALGORITHM_NAME;
		if(!(params instanceof BBS98ReKeyGenParameterSpec)){
			throw new InvalidAlgorithmParameterException();
		} 
		this.params = (BBS98ReKeyGenParameterSpec) params;
		
	}

	@Override
	public ReEncryptionKey generateReEncryptionKey() {
		ECPrivateKey skA = (ECPrivateKey) this.params.getDelegator();
		ECPrivateKey skB = (ECPrivateKey) this.params.getDelegatee();
		
		BigInteger n = this.params.getCurve().getN();
		BigInteger inv_sk_a = skA.getD().modInverse(n);
		BigInteger rk = skB.getD().multiply(inv_sk_a).mod(n);
		
		return new BBS98ReEncryptionKey(rk, n);
	}

}
