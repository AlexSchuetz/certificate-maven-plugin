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

/**
 *
 */
public class KeyStoreParameters {

    private final String alias;
    
    private final String storePassword;
    
    private final String keyPassword;
    
    private final File outputDirectory;

    private final String keyStoreName;
    public KeyStoreParameters(String keyStoreName, String alias, String storePassword, String keyPassword, File outputDirectory) {
        this.keyStoreName = keyStoreName;
        this.alias = alias;
        this.storePassword = storePassword;
        this.keyPassword = keyPassword;
        this.outputDirectory = outputDirectory;
    }

    public String getKeyStoreName() {
        return keyStoreName;
    }
    
    
    
    public String getAlias() {
        return alias;
    }

    public File getOutputDirectory() {
        return outputDirectory;
    }

    
    
    public String getStorePassword() {
        return storePassword;
    }

    public String getKeyPassword() {
        return keyPassword;
    }
    
    
}
