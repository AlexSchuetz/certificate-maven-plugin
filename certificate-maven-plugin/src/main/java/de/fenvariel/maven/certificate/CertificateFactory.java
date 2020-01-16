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

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


public class CertificateFactory {

    private final PrivateKey issuerPrivateKey;
    private final X509Certificate[] issuerChain;

    public CertificateFactory(PrivateKey issuerPrivateKey, X509Certificate... issuerChain) {
        this.issuerPrivateKey = issuerPrivateKey;
        if (issuerChain == null) {
            this.issuerChain = new X509Certificate[0];
        } else {
            this.issuerChain = issuerChain;
        }
    }

    public X509Certificate[] createCACertificateChain(int pathLength, Date notBefore, Date notAfter, X500Principal subjectDN, PublicKey subjectPublicKey)
            throws GeneralSecurityException, CertIOException, OperatorCreationException {

        return createChain(createCACertificate(pathLength, notBefore, notAfter, subjectDN, subjectPublicKey));
    }

    public X509Certificate[] createClientCertificateChain(Date notBefore, Date notAfter, X500Principal subjectDN, PublicKey subjectPublicKey)
            throws GeneralSecurityException, CertIOException, OperatorCreationException {

        return createChain(createClientCertificate(notBefore, notAfter, subjectDN, subjectPublicKey));
    }

    public X509Certificate[] createCACertificateChain(int pathLength, Date notBefore, int days, X500Principal subjectDN, PublicKey subjectPublicKey)
            throws GeneralSecurityException, CertIOException, OperatorCreationException {

        return createChain(createCACertificate(pathLength, notBefore, notAfter(notBefore, days), subjectDN, subjectPublicKey));
    }

    public X509Certificate[] createServerCertificateChain(Date notBefore, int days, X500Principal subjectDN, PublicKey subjectPublicKey, String alternativeName)
            throws GeneralSecurityException, CertIOException, OperatorCreationException {

        return createChain(createServerCertificate(notBefore, notAfter(notBefore, days), subjectDN, subjectPublicKey, alternativeName));
    }

    public X509Certificate[] createClientCertificateChain(Date notBefore, int days, X500Principal subjectDN, PublicKey subjectPublicKey)
            throws GeneralSecurityException, CertIOException, OperatorCreationException {

        return createChain(createClientCertificate(notBefore, notAfter(notBefore, days), subjectDN, subjectPublicKey));
    }

    private BigInteger createX509Serial() {
        UUID uuid = UUID.randomUUID();
        ByteBuffer buffer = ByteBuffer.allocate(16);
        buffer.putLong(uuid.getMostSignificantBits());
        buffer.putLong(uuid.getLeastSignificantBits());
        return new BigInteger(buffer.array());
    }

    private X509Certificate[] createChain(X509Certificate newCertificate)
            throws GeneralSecurityException, CertIOException, OperatorCreationException {
        X509Certificate[] chain = new X509Certificate[issuerChain.length+1];
        System.arraycopy(issuerChain, 0, chain, 1, issuerChain.length);
        chain[0] = newCertificate;
        return chain;
    }

    private Date notAfter(Date notBefore, int days) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(notBefore);
        calendar.add(Calendar.DAY_OF_YEAR, days);
        return calendar.getTime();
    }

    private X509v3CertificateBuilder prepareBuilder(Date notBefore, Date notAfter, X500Principal subjectDN, PublicKey subjectPublicKey) throws GeneralSecurityException, CertIOException {

        //Serial Number
        BigInteger serial = createX509Serial();

        X500Principal issuerDN;
        PublicKey issuerPublicKey;

        if (issuerChain != null && issuerChain.length > 0) {
            // no selfsigned certificate so use the last certificate in the caChain
            issuerDN = issuerChain[0].getSubjectX500Principal();
            issuerPublicKey = issuerChain[0].getPublicKey();
        } else {
            // selfsigned certificate so use subject PublicKey as issuer PublicKey and subjectDN as IssuerDN
            issuerDN = subjectDN;
            issuerPublicKey = subjectPublicKey;
        }

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerDN, serial, notBefore, notAfter, subjectDN, subjectPublicKey);
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        //Subject Key Identifier
        builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectPublicKey));

        //Authority Key Identifier
        builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuerPublicKey));
        return builder;
    }

    private X509Certificate createCACertificate(int pathLength, Date notBefore, Date notAfter, X500Principal subjectDN, PublicKey subjectPublicKey)
            throws GeneralSecurityException,
                   CertIOException,
                   OperatorCreationException {

        X509v3CertificateBuilder builder = prepareBuilder(notBefore, notAfter, subjectDN, subjectPublicKey);

        addCACertificateExtensions(builder, pathLength);

        X509Certificate certificate = sign(builder);
        verify(certificate);

        return certificate;
    }
    
    private X509Certificate createServerCertificate(Date notBefore, Date notAfter, X500Principal subjectDN, PublicKey subjectPublicKey, String alternativeName)
            throws GeneralSecurityException,
                   CertIOException,
                   OperatorCreationException {

        X509v3CertificateBuilder builder = prepareBuilder(notBefore, notAfter, subjectDN, subjectPublicKey);

        addServerCertificateExtensions(builder, alternativeName);

        X509Certificate certificate = sign(builder);
        verify(certificate);

        return certificate;
    }

    private X509Certificate createClientCertificate(Date notBefore, Date notAfter, X500Principal subjectDN, PublicKey subjectPublicKey)
            throws GeneralSecurityException,
                   CertIOException,
                   OperatorCreationException {

        X509v3CertificateBuilder builder = prepareBuilder(notBefore, notAfter, subjectDN, subjectPublicKey);

        addClientCertificateExtensions(builder);

        X509Certificate certificate = sign(builder);
        verify(certificate);

        return certificate;
    }

    private X509Certificate sign(X509v3CertificateBuilder builder) throws CertificateException, OperatorCreationException {
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);
        X509CertificateHolder certificateHolder = builder.build(contentSigner);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        return converter.getCertificate(certificateHolder);
    }

    private void verify(X509Certificate certificate) throws GeneralSecurityException {
        PublicKey issuerPublicKey;
        if (issuerChain != null && issuerChain.length > 0) {
            issuerPublicKey = issuerChain[0].getPublicKey();
        } else {
            issuerPublicKey = certificate.getPublicKey();
        }
        certificate.checkValidity(new Date());
        certificate.verify(issuerPublicKey);
    }

    private void addCACertificateExtensions(X509v3CertificateBuilder builder, int pathLength) throws CertIOException {
        //Key Usage
        KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign);
        builder.addExtension(Extension.keyUsage, true, usage);

        //Basic Constraints
        BasicConstraints basicConstraints = new BasicConstraints(pathLength);
        builder.addExtension(Extension.basicConstraints, true, basicConstraints);
    }
    
    private void addServerCertificateExtensions(X509v3CertificateBuilder builder, String dnsName) throws CertIOException {
        //Key Usage
        KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature);
        builder.addExtension(Extension.keyUsage, true, usage);

        //Basic Constraints
        BasicConstraints basicConstraints = new BasicConstraints(false);
        builder.addExtension(Extension.basicConstraints, true, basicConstraints);
        
        GeneralNames subjectAltNames = new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName));
        builder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
        
        ExtendedKeyUsage extendedUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth);
        builder.addExtension(Extension.extendedKeyUsage, false, extendedUsage);
    }

    private void addClientCertificateExtensions(X509v3CertificateBuilder builder) throws CertIOException {
        //Key Usage
        KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.nonRepudiation);
        builder.addExtension(Extension.keyUsage, true, usage);

        //Basic Constraints
        BasicConstraints basicConstraints = new BasicConstraints(false);
        builder.addExtension(Extension.basicConstraints, false, basicConstraints);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.id_kp_emailProtection);
        builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));
    }
}

