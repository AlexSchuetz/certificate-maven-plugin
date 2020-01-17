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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.pem.PemObject;

public class CertificateService {

    private PrivateKey caPrivateKey;
    private X509Certificate[] caChain;
    
    public CertificateService(File keystoreFile, String storeType, char[] keystorePassword, String alias, char[] keyPassword) throws IOException, GeneralSecurityException {
        KeyStore mainKeyStore = KeyStore.getInstance(storeType);
        mainKeyStore.load(new FileInputStream(keystoreFile), keystorePassword);

        this.caPrivateKey = (PrivateKey) mainKeyStore.getKey(alias, keyPassword);
        java.security.cert.Certificate[] certificateChain = mainKeyStore.getCertificateChain(alias);
        this.caChain = new X509Certificate[certificateChain.length];
        for (int i = 0; i < certificateChain.length; ++i) {
            this.caChain[i] = (X509Certificate) certificateChain[i];
        }
    }

    public void generateServerCertificate(CertificateParameters parameters, KeyStoreParameters keyStoreParameters) throws NoSuchAlgorithmException, NoSuchProviderException, GeneralSecurityException, CertIOException, OperatorCreationException, IOException, Exception {
        CertificateFactory factory = new CertificateFactory(caPrivateKey, caChain);

        KeyPair keyPair = CryptoUtil.generateKeyPair(parameters.getKeySize(), parameters.getKeyAlgorithm());
        X500Principal principal = new X500PrincipalBuilder()
                .setCommonName(parameters.getCommonName())
                .setCountry(parameters.getCountryCode())
                .setLocality(parameters.getLocality())
                .setOrganisation(parameters.getOrganisation())
                .setOrganisationalUnit(parameters.getOrganisationalUnit())
                .setState(parameters.getState())
                .setEmailAddress(parameters.getMailAddress())
                .setUID(parameters.getUid()).build();

        ZoneId utc = ZoneId.of("Z");
        LocalDate yesterdayUTC = LocalDate.now(utc).minusDays(2);
        Date from = Date.from(yesterdayUTC.atStartOfDay(utc).toInstant());
        X509Certificate[] chain = factory.createServerCertificateChain(from, parameters.getValidityDuration(), principal, keyPair.getPublic(), parameters.getAlternativeName());
    
        writeJKS(keyStoreParameters, keyPair.getPrivate(), chain);
        writePKCS(keyStoreParameters, keyPair.getPrivate(), chain);
        writePEM(keyStoreParameters, keyPair.getPrivate(), chain);
    }
    
    private void writePEM(KeyStoreParameters keyStoreParameters, PrivateKey key, X509Certificate[] chain) throws CertificateEncodingException, IOException {
        File crtFile = new File(keyStoreParameters.getOutputDirectory(), keyStoreParameters.getKeyStoreName() + ".crt");
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(crtFile))) {
            for (X509Certificate cert : chain) {
                pemWriter.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
            }
            pemWriter.flush();
            pemWriter.close();
        }
        File keyFile = new File(keyStoreParameters.getOutputDirectory(), keyStoreParameters.getKeyStoreName() + ".key");
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(keyFile))) {
            pemWriter.writeObject(new PemObject("PRIVATE KEY", key.getEncoded()));
            pemWriter.flush();
            pemWriter.close();
        }
    }
    
    private void writeJKS(KeyStoreParameters keyStoreParameters, PrivateKey key, X509Certificate[] chain) throws GeneralSecurityException, IOException, Exception {
        File jksOutFile = new File(keyStoreParameters.getOutputDirectory(), keyStoreParameters.getKeyStoreName() + ".jks");
        KeyStoreBuilder ksBuilder = new KeyStoreBuilder("BKS");
        write(ksBuilder, keyStoreParameters, key, chain, jksOutFile);
    }
    
    private void writePKCS(KeyStoreParameters keyStoreParameters, PrivateKey key, X509Certificate[] chain) throws GeneralSecurityException, IOException, Exception {
        File pkcsOutFile = new File(keyStoreParameters.getOutputDirectory(), keyStoreParameters.getKeyStoreName() + ".p12");
        KeyStoreBuilder ksBuilder = new KeyStoreBuilder(KeyStoreBuilder.TYPE_PKCS12);
        write(ksBuilder, keyStoreParameters, key, chain, pkcsOutFile);
    }
    private void write(KeyStoreBuilder ksBuilder, KeyStoreParameters keyStoreParameters, PrivateKey key, X509Certificate[] chain, File file) throws Exception {
        ksBuilder.addPrivateKey(keyStoreParameters.getAlias(), key, chain, keyStoreParameters.getKeyPassword().toCharArray());
        byte[] data = ksBuilder.buildBlob(keyStoreParameters.getStorePassword().toCharArray());
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(data);
        fos.flush();
        fos.close();
    }
    
}
