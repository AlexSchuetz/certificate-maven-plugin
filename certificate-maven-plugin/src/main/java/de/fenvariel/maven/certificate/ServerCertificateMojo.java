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
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * Generates a server certificate and signed by a given CA. The result will be:
 * <ul>
 *   <li>a password protected java keystore (*.jks) containing the private key and the certificate chain</li>
 *   <li>a password protected PKCS 1.2 keystore (*.p12) containing the private key and the certificate chain</li>
 *   <li>an unprotected PEM-file containing the private key (*.key)</li>
 *   <li>a PEM-file containing the chertificate chain (*.crt)</li>
 * </ul>
 */
@Mojo(name = "generateServer", defaultPhase = LifecyclePhase.GENERATE_RESOURCES)
public class ServerCertificateMojo extends AbstractCertificateMojo {

    @Parameter(property = "project.build.outputDirectory", required = true)
    protected File outputDirectory;

    /**
     * The name for the output files keystore_name.jks, keystore_name.p12,
     * keystore_name.key and keystore_name.crt
     */
    @Parameter(defaultValue = "server")
    private String keystore_name;

    /**
     * The keystore in which the CA-certificate and its key is stored.
     */
    @Parameter(required = true)
    private File ca_keystore;

    /**
     * Keystore type of the keystore containing the CA. (i.e. JKS, PKCS12) 
     */
    @Parameter(defaultValue = "JKS")
    private String ca_storetype;

    /**
     * Password for the keystore containing the CA.
     */
    @Parameter(defaultValue = "changeit")
    private String ca_storepass;
    
    /**
     * Password for the CA key.
     */
    @Parameter(defaultValue = "changeit")
    private String ca_keypass;
    
    
    /**
     * Alias of the CA key in the CA-keystore. (defaults to ca)
     */
    @Parameter(defaultValue = "ca")
    private String ca_alias;
    
    /**
     * The CN for the certificate.
     */
    @Parameter(required = true)
    private String common_name;
    
    /**
     * (optional) The subject countrycode for the certificate.
     */
    @Parameter(defaultValue = "")
    private String country_code;
    
    /**
     * (optional) The subject locality for the certificate.
     */
    @Parameter(defaultValue = "")
    private String locality;
    
    /**
     * (optional) The subject organisation for the certificate.
     */
    @Parameter(defaultValue = "")
    private String organisation;
    
    /**
     * (optional) The subject organisational unit for the certificate.
     */
    @Parameter(defaultValue = "")
    private String organisational_unit;
    
    /**
     * (optional) The subject state for the certificate.
     */
    @Parameter(defaultValue = "")
    private String state;
    
    /**
     * (optional) The subject mail address for the certificate.
     */
    @Parameter(defaultValue = "")
    private String mail_address;
    
    /**
     * (optional) The subject uid for the certificate.
     */
    @Parameter(defaultValue = "")
    private String uid;
    
    /**
     * (optional) The validity duration for the certificate (starting the day
     * before yesterday in UTC).
     */
    @Parameter(defaultValue = "30")
    private int validity_duration;
    
    /**
     * If the subject CN should already used subjectAlternativeName. (defaults to true)
     */
    @Parameter(defaultValue = "true")
    private boolean alternative_name;
    
    /**
     * The alias for the entry in the output keystores. (defaults to server
     */
    @Parameter(defaultValue = "server")
    private String cert_alias;

    /**
     * The password for the output keystores. (defaults to changeit).
     * <p>
     * Note that some servers may require that all entries in the keystore are
     * secured with the same password as the keystore itself!
     * 
     */
    @Parameter(defaultValue = "changeit")
    private String cert_storepass;
    
    /**
     * The password for the entry in the output keystores. (defaults to changeit).
     * <p>
     * Note that some servers may require that all entries in the keystore are
     * secured with the same password as the keystore itself!
     * 
     */
    @Parameter(defaultValue = "changeit")
    private String cert_keypass;
    
    @Override
    public void execute() throws MojoExecutionException {

        try {
            // create output directory if it doesn't exists
            outputDirectory.mkdirs();
            
            CertificateService certificateService = new CertificateService(ca_keystore, ca_storetype, ca_storepass.toCharArray(), ca_alias, ca_keypass.toCharArray());
            KeyStoreParameters keyStoreParameters = new KeyStoreParameters(keystore_name, cert_alias, cert_storepass, cert_keypass, outputDirectory);
            CertificateParameters certificateParameters = new CertificateParameters(1024, common_name, country_code, locality, organisation, organisational_unit, state, mail_address, uid, (alternative_name ? common_name : null), validity_duration);
            certificateService.generateServerCertificate(certificateParameters, keyStoreParameters);
        } catch (Exception ex) {
            Logger.getLogger(ServerCertificateMojo.class.getName()).log(Level.SEVERE, null, ex);
            throw new MojoExecutionException(ex.getMessage());
        }
    }
}
