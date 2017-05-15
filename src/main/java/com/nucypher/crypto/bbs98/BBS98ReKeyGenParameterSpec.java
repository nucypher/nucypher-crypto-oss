package com.nucypher.crypto.bbs98;

import java.security.PrivateKey;

import org.bouncycastle.jce.spec.ECParameterSpec;

public class BBS98ReKeyGenParameterSpec extends BBS98ParameterSpec {

	private PrivateKey delegator, delegatee;
	
	public BBS98ReKeyGenParameterSpec(ECParameterSpec c, PrivateKey delegator, PrivateKey delegatee) {
		super(c);
		this.delegator = delegator;
		this.delegatee = delegatee;
	}

	public PrivateKey getDelegator() {
		return delegator;
	}

	public PrivateKey getDelegatee() {
		return delegatee;
	}
	
}
