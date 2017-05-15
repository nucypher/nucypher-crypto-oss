package com.nucypher.crypto.bbs98;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jce.spec.ECParameterSpec;

public class BBS98ParameterSpec implements AlgorithmParameterSpec {
	private ECParameterSpec curve;
	
	public BBS98ParameterSpec(ECParameterSpec c){
		curve = c;
	}
	
	public ECParameterSpec getCurve() {
		return curve;
	}
	
}
