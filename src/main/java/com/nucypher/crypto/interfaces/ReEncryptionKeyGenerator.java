package com.nucypher.crypto.interfaces;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import com.nucypher.crypto.bbs98.BBS98BouncyCastle;
import com.nucypher.crypto.bbs98.BBS98ReEncryptionKeyGenerator;

public abstract class ReEncryptionKeyGenerator {
	
    protected String algorithm;
    
    //protected ReEncryptionKeyGenerator(String algorithm) {
    //    this.algorithm = algorithm;
    //}
    
    public String getAlgorithm() {
        return algorithm;
    }
	
    public ReEncryptionKeyGenerator getInstance(String algorithm){
    	if(BBS98BouncyCastle.ALGORITHM_NAME.equals(algorithm)){
    		return new BBS98ReEncryptionKeyGenerator();
    	}
    	return null;
    }
    
	public abstract void initialize(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException;
	
	public abstract ReEncryptionKey generateReEncryptionKey();
	
}
