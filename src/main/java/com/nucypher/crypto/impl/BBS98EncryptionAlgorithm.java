package com.nucypher.crypto.impl;

import com.nucypher.crypto.AlgorithmName;
import com.nucypher.crypto.EncryptionAlgorithm;
import com.nucypher.crypto.bbs98.BBS98ReEncryptionKeyGenerator;
import com.nucypher.crypto.bbs98.BBS98ReKeyGenParameterSpec;
import com.nucypher.crypto.bbs98.WrapperBBS98;
import com.nucypher.crypto.interfaces.ReEncryptionKey;
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
 * BBS98 implementation of {@link EncryptionAlgorithm}
 */
@AlgorithmName("BBS98")
public class BBS98EncryptionAlgorithm implements EncryptionAlgorithm {

    @Override
    public KeyPair generateECKeyPair(ECParameterSpec ecParameterSpec) {
        WrapperBBS98 wrapper = new WrapperBBS98(ecParameterSpec, new SecureRandom());
        try {
            return wrapper.keygen();
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public BigInteger generateReEncryptionKey(PrivateKey privateKeyFrom, PrivateKey privateKeyTo) {
        ECParameterSpec ecParameterSpec = ((ECPrivateKey) privateKeyFrom).getParameters();
        BBS98ReKeyGenParameterSpec params = new BBS98ReKeyGenParameterSpec(
                ecParameterSpec, privateKeyFrom, privateKeyTo);
        BBS98ReEncryptionKeyGenerator bbs98Generator = new BBS98ReEncryptionKeyGenerator();
        try {
            bbs98Generator.initialize(params);
        } catch (InvalidAlgorithmParameterException e) {
            //unreachable code
            throw new RuntimeException(e);
        }

        ReEncryptionKey key = bbs98Generator.generateReEncryptionKey();
        return new BigInteger(key.getEncoded());
    }

    @Override
    public byte[] encrypt(PublicKey publicKey, byte[] data, SecureRandom secureRandom) {
        ECParameterSpec ecParameterSpec = ((ECPublicKey) publicKey).getParameters();
        WrapperBBS98 wrapper = new WrapperBBS98(ecParameterSpec, secureRandom);
        return wrapper.encrypt(publicKey, data);
    }

    @Override
    public byte[] decrypt(PrivateKey privateKey, byte[] data) {
        ECParameterSpec ecParameterSpec = ((ECPrivateKey) privateKey).getParameters();
        WrapperBBS98 wrapper = new WrapperBBS98(ecParameterSpec, null);
        return wrapper.decrypt(privateKey, data);
    }

    @Override
    public byte[] reEncrypt(BigInteger reEncryptionKey,
                            ECParameterSpec ecParameterSpec,
                            byte[] data) {
        WrapperBBS98 wrapperBBS98 = new WrapperBBS98(ecParameterSpec, null);
        return wrapperBBS98.reencrypt(reEncryptionKey, data);
    }
}
