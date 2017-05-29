package com.nucypher.crypto;

import org.bouncycastle.jce.spec.ECParameterSpec;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * Interface for EC encryption algorithm wrapper.
 * The implementation must be located at ${@link com.nucypher.crypto} package
 * or subpackage for auto configuration.
 * The implementation must have default constructor
 */
public interface EncryptionAlgorithm {

    /**
     * Generate EC key pair
     *
     * @param ecParameterSpec EC parameters
     * @return EC key pair
     */
    public KeyPair generateECKeyPair(ECParameterSpec ecParameterSpec);

    /**
     * Generate re-encryption key
     *
     * @param privateKeyFrom first EC private key
     * @param privateKeyTo   second EC private key
     * @return re-encryption key
     */
    public BigInteger generateReEncryptionKey(PrivateKey privateKeyFrom, PrivateKey privateKeyTo);

    /**
     * Encrypt data
     *
     * @param publicKey    EC public key
     * @param data         data
     * @param secureRandom secure random
     * @return encrypted data
     */
    public byte[] encrypt(PublicKey publicKey, byte[] data, SecureRandom secureRandom);

    /**
     * Decrypt data
     *
     * @param privateKey EC private key
     * @param data       data
     * @return decrypted data
     */
    public byte[] decrypt(PrivateKey privateKey, byte[] data);

    /**
     * Re-encrypt data
     *
     * @param reEncryptionKey re-encryption key
     * @param ecParameterSpec EC parameters
     * @param data            encrypted data
     * @return re-encrypted data
     */
    public byte[] reEncrypt(BigInteger reEncryptionKey,
                            ECParameterSpec ecParameterSpec,
                            byte[] data);

}