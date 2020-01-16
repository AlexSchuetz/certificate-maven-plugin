/*
 * Copyright 2020 Alexander Schütz.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.fenvariel.maven.certificate;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;

public final class CryptoUtil {

    private static final int DEFAULT_KEYSIZE = 2048;

    static {
        if (!isBouncyCastleInstalled()) {
            try {
                Security.addProvider(new BouncyCastleProvider());
            } catch (Exception e) {
            }
        }
    }

    public static boolean isBouncyCastleInstalled() {
        return Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) != null;
    }

    public static boolean isUnlimitedStrengthJurisdicationPolicy() {
        try {
            return Cipher.getMaxAllowedKeyLength("DES") > 64;
        } catch (NoSuchAlgorithmException des) {
            try {
                return Cipher.getMaxAllowedKeyLength("AES") > 128;
            } catch (NoSuchAlgorithmException aes) {
                return false;
            }
        }
    }

    /**
     * reads a private key from a given .pem file
     *
     * @param privateKeyFile the PEM-File holding the private key
     *
     * @return the private key object
     *
     * @throws IOException if the file cannot be read
     */
    public static PrivateKey readPrivateKey(File privateKeyFile) throws IOException {
        FileReader privateKeyFileReader = null;
        PEMParser pemParser = null;

        try {
            privateKeyFileReader = new FileReader(privateKeyFile);
            pemParser = new PEMParser(privateKeyFileReader);
            final KeyPair keypair = (KeyPair) pemParser.readObject();
            return keypair.getPrivate();
        } finally {
            if (pemParser != null) {
                pemParser.close();
            }
            if (privateKeyFileReader != null) {
                privateKeyFileReader.close();
            }
        }
    }

    /**
     * reads a X509 certificate from a given .pem file
     *
     * @param certificateFile the PEM-File holding the certificate
     *
     * @return the X509Certificate object
     *
     * @throws IOException if the file cannot be read
     */
    public static X509Certificate readX509Certificate(File certificateFile) throws IOException {
        FileReader certificateFileReader = null;
        PEMParser pemParser = null;

        try {
            certificateFileReader = new FileReader(certificateFile);
            pemParser = new PEMParser(certificateFileReader);
            return (X509Certificate) pemParser.readObject();
        } finally {
            if (pemParser != null) {
                pemParser.close();
            }
            if (certificateFileReader != null) {
                certificateFileReader.close();
            }
        }
    }

    /**
     * reads a X509 certificate from a given .pem file
     *
     * @param buffer encoded X509Certificate
     *
     * @return the X509Certificate
     *
     * @throws java.security.cert.CertificateException on parsing errors
     */
    public static X509Certificate readX509Certificate(byte[] buffer) throws CertificateException {
        java.security.cert.CertificateFactory certFactory = java.security.cert.CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(buffer));
    }

    /**
     * generates a RSA-key pair (private key, public key) with a default
     * keysize.
     *
     * @return KeyPair the keypair
     *
     * @throws NoSuchAlgorithmException if no provider supports a
     *                                  KeyPairGeneratorSpi implementation for
     *                                  RSA
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        return generateKeyPair(DEFAULT_KEYSIZE);
    }

    /**
     * generates a RSA-key pair with the given key-size
     *
     * @param keySize the keysize (i.e. 1024)
     *
     * @return KeyPair the keypair
     *
     * @throws NoSuchAlgorithmException if no provider supports a
     *                                  KeyPairGeneratorSpi implementation for
     *                                  RSA
     */
    public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {

        KeyPairGenerator pairgen = KeyPairGenerator.getInstance("RSA");
        pairgen.initialize(keySize);

        return pairgen.generateKeyPair();
    }

    /**
     * A Signature object may have three states: UNINITIALIZED SIGN VERIFY
     * <p>
     * First created: a Signature object is in the UNINITIALIZED state. There
     * are two initialization methods: initSign and initVerify, which change the
     * state to SIGN or to VERIFY.<p>
     * With the private key you sign the data, with the public key you verify
     * the signed data.<p>
     *
     * @param privKey    the private key to sign with
     * @param originData the data to be signed
     *
     * @return signed data {byte[]}
     *
     * @throws NoSuchAlgorithmException          if no Provider supports a
     *                                           Signature implementation for
     *                                           the specified algorithm.
     * @throws java.security.InvalidKeyException if the key is invalid.
     * @throws java.security.SignatureException  if this signature object is not
     *                                           initialized properly or if this
     *                                           signature algorithm is unable
     *                                           to process the input data
     *                                           provided.
     */
    public static byte[] sign(PrivateKey privKey, byte[] originData)
            throws NoSuchAlgorithmException,
                   InvalidKeyException,
                   SignatureException {

        Signature sign = Signature.getInstance("SHA256withRSA");
        byte[] updatedData = null;

        /* Initializing the object with a private key */
        sign.initSign(privKey);

        /* Update and sign the data */
        sign.update(originData);

        updatedData = sign.sign();

        return updatedData;
    }

    /**
     * takes bytes of PrivateKey saved in database and converts back to
     * PrivateKey.
     *
     * @param savedKey the private key bytes
     *
     * @return PrivateKey the private key
     *
     * @throws NoSuchAlgorithmException if no Provider supports a KeyFactorySpi
     *                                  implementation for the RSA-algorithm.
     * @throws InvalidKeySpecException  if the given key specification is
     *                                  inappropriate for this key factory to
     *                                  produce a private key.
     */
    public static PrivateKey getPrivateKeyByBytes(byte[] savedKey) throws NoSuchAlgorithmException,
                                                                          InvalidKeySpecException {

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(savedKey);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PrivateKey privKey = keyFactory.generatePrivate(keySpec);

        return privKey;
    }

    /**
     * takes bytes of PublicKey saved in database and converts back to
     * PublicKey.
     *
     * @param savedKey the public key bytes
     *
     * @return PublicKey the public key
     *
     * @throws NoSuchAlgorithmException if no Provider supports a KeyFactorySpi
     *                                  implementation for the RSA-algorithm.
     * @throws InvalidKeySpecException  if the given key specification is
     *                                  inappropriate for this key factory to
     *                                  produce a private key.
     */
    public static PublicKey getPublicKeyByBytes(byte[] savedKey) throws NoSuchAlgorithmException,
                                                                        InvalidKeySpecException {

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(savedKey);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        return publicKey;
    }

    private CryptoUtil() {
    }
}
