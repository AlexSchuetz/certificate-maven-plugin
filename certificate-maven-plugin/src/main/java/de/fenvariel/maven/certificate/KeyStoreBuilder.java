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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.commons.io.input.AutoCloseInputStream;

public class KeyStoreBuilder {

    public static final String TYPE_PKCS12 = "PKCS12";
    public static final String TYPE_JKS = "JKS";

    private final KeyStore keyStore;


    public static boolean isSuitableForAndroid() {
        return CryptoUtil.isBouncyCastleInstalled()
                && CryptoUtil.isUnlimitedStrengthJurisdicationPolicy();
    }

    public KeyStoreBuilder(String type) throws GeneralSecurityException, IOException {
        this.keyStore = KeyStore.getInstance(type, "BC");
        this.keyStore.load(null, null);
    }

    public KeyStoreBuilder addPrivateKey(String alias, byte[] key, X509Certificate[] chain, char[] password) throws GeneralSecurityException {
        PrivateKey privateKey = null;
        if (key != null) {
            privateKey = CryptoUtil.getPrivateKeyByBytes(key);
        }
        this.keyStore.setKeyEntry(alias, privateKey, password, chain);
        return this;
    }
    
    public KeyStoreBuilder addPrivateKey(String alias, PrivateKey privateKey, X509Certificate[] chain, char[] password) throws GeneralSecurityException {
        this.keyStore.setKeyEntry(alias, privateKey, password, chain);
        return this;
    }

    public KeyStore build() {
        return keyStore;
    }

    public InputStream buildStream(char[] password) throws Exception {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            if (password != null && password.length > 0) {
                this.keyStore.store(bos, password);
            } else {
                this.keyStore.store(bos, new char[0]);
            }
            return new AutoCloseInputStream(new ByteArrayInputStream(bos.toByteArray()));
        } catch (GeneralSecurityException | IOException ex) {
            throw new Exception("cannot create keystore: ", ex);
        }
    }

    public byte[] buildBlob(char[] password) throws Exception {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            if (password != null && password.length > 0) {
                this.keyStore.store(bos, password);
            } else {
                this.keyStore.store(bos, new char[0]);
            }
            return bos.toByteArray();
        } catch (GeneralSecurityException | IOException ex) {
            throw new Exception("cannot create keystore: ", ex);
        }
    }
}
