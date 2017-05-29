package com.nucypher.crypto.impl;

import com.nucypher.crypto.AlgorithmName;
import com.nucypher.crypto.EncryptionAlgorithm;
import com.nucypher.crypto.elgamal.ElGamalReEncryptionKeyGenerator;
import com.nucypher.crypto.elgamal.WrapperElGamalPRE;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * ElGamal implementation of {@link EncryptionAlgorithm}
 */
@AlgorithmName("ElGamal")
public class ElGamalEncryptionAlgorithm implements EncryptionAlgorithm {

    @Override
    public KeyPair generateECKeyPair(ECParameterSpec ecParameterSpec) {
        WrapperElGamalPRE wrapper = new WrapperElGamalPRE(ecParameterSpec, new SecureRandom());
        try {
            return wrapper.keygen();
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public BigInteger generateReEncryptionKey(PrivateKey privateKeyFrom, PrivateKey privateKeyTo) {
        ECParameterSpec ecParameterSpec = ((ECPrivateKey) privateKeyFrom).getParameters();
        return ElGamalReEncryptionKeyGenerator.generateReEncryptionKey(
                privateKeyFrom, privateKeyTo, ecParameterSpec);
    }

    @Override
    public byte[] encrypt(PublicKey publicKey, byte[] data, SecureRandom secureRandom) {
        ECParameterSpec ecParameterSpec = ((ECPublicKey) publicKey).getParameters();
        WrapperElGamalPRE wrapper = new WrapperElGamalPRE(ecParameterSpec, secureRandom);
        return wrapper.encrypt(publicKey, data);
    }

    @Override
    public byte[] decrypt(PrivateKey privateKey, byte[] data) {
        ECParameterSpec ecParameterSpec = ((ECPrivateKey) privateKey).getParameters();
        WrapperElGamalPRE wrapper = new WrapperElGamalPRE(ecParameterSpec, null);
        return wrapper.decrypt(privateKey, data);
    }

    @Override
    public byte[] reEncrypt(BigInteger reEncryptionKey,
                            ECParameterSpec ecParameterSpec,
                            byte[] data) {
        WrapperElGamalPRE wrapper = new WrapperElGamalPRE(ecParameterSpec, null);
        return wrapper.reencrypt(reEncryptionKey, data);
    }
}
