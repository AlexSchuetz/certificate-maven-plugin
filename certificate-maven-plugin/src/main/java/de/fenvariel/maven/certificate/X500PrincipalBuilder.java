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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x500.style.RFC4519Style;

public final class X500PrincipalBuilder {

    /* OID 2.5.4.3 - StringType(SIZE(1..64)) */
    private static final ASN1ObjectIdentifier COMMON_NAME = RFC4519Style.cn;
    /* OID 2.5.4.6 - StringType(SIZE(2)) */
    private static final ASN1ObjectIdentifier COUNTRY = RFC4519Style.c;
    /* OID 2.5.4.8 - StringType(SIZE(1..64)) */
    private static final ASN1ObjectIdentifier STATE = RFC4519Style.st;
    /* OID 2.5.4.7 - StringType(SIZE(1..64)) */
    private static final ASN1ObjectIdentifier LOCALITY = RFC4519Style.l;
    /* OID 2.5.4.10 - StringType(SIZE(1..64)) */
    private static final ASN1ObjectIdentifier ORGANISATION = RFC4519Style.o;

    private static final ASN1ObjectIdentifier DOMAIN_COMPONENT = RFC4519Style.dc;
    /* OID 2.5.4.11 - StringType(SIZE(1..64)) */
    private static final ASN1ObjectIdentifier ORGANISATIONAL_UNIT = RFC4519Style.ou;
    /* OID 1.2.840.113549.1.9.1 - IA5String */
    private static final ASN1ObjectIdentifier EMAIL_ADDRESS = PKCSObjectIdentifiers.pkcs_9_at_emailAddress;

    private static final ASN1ObjectIdentifier UID = RFC4519Style.uid;
    /* Order! */
    private static final ASN1ObjectIdentifier[] ORDER = new ASN1ObjectIdentifier[]{COUNTRY, STATE, LOCALITY, ORGANISATION, ORGANISATIONAL_UNIT, COMMON_NAME, UID, EMAIL_ADDRESS, DOMAIN_COMPONENT};

    public static String getCommonName(X500Principal principal) {
        return extractFromX500Name(asX500Name(principal), COMMON_NAME);
    }

    public static String getUID(X500Principal principal) {
        return extractFromX500Name(asX500Name(principal), UID);
    }

    public static String getCountry(X500Principal principal) {
        return extractFromX500Name(asX500Name(principal), COUNTRY);
    }

    public static String getLocality(X500Principal principal) {
        return extractFromX500Name(asX500Name(principal), LOCALITY);
    }

    public static String getOrganisation(X500Principal principal) {
        return extractFromX500Name(asX500Name(principal), ORGANISATION);
    }

    public static String getDomainComponent(X500Principal principal) {
        return extractFromX500Name(asX500Name(principal), DOMAIN_COMPONENT);
    }

    public static String getOrganisationalUnit(X500Principal principal) {
        return extractFromX500Name(asX500Name(principal), ORGANISATIONAL_UNIT);
    }

    public static String getState(X500Principal principal) {
        return extractFromX500Name(asX500Name(principal), STATE);
    }

    public static String getEmailAddress(X500Principal principal) {
        return extractFromX500Name(asX500Name(principal), EMAIL_ADDRESS);
    }

    private static String extractFromX500Name(X500Name name, ASN1ObjectIdentifier identifier) {
        RDN[] rdns = name.getRDNs(identifier);
        if (rdns == null || rdns.length == 0) {
            return null;
        }
        return decode(rdns);
    }

    private static X500Name asX500Name(X500Principal principal) {
        return X500Name.getInstance(principal.getEncoded());
    }

    private static String decode(RDN[] rdns) {
        StringBuilder sb = new StringBuilder();
        for (RDN rdn : rdns) {
            for (AttributeTypeAndValue typeAndValue : rdn.getTypesAndValues()) {
                sb.append(IETFUtils.valueToString(typeAndValue.getValue())).append(" ");
            }
        }
        return sb.toString().trim();
    }

    private final Map<ASN1ObjectIdentifier, ASN1Primitive> attributes;

    /**
     * Create a new {@link X500PrincipalBuilder} instance.
     */
    public X500PrincipalBuilder() {
        attributes = new HashMap<>();
    }

    /**
     * Create a new {@link X500PrincipalBuilder} instance with COUNTRY,
     * DOMAIN_COMPONENT, LOCALITY, ORGANISATION, ORGANISATIONAL_UNIT and STATE
     * attributes of the given DN.
     *
     * @param dn dirName
     */
    public X500PrincipalBuilder(String dn) {
        this();
        X500Name name = new X500Name(dn);
        setCountry(extractFromX500Name(name, COUNTRY));
        setDomainComponent(extractFromX500Name(name, DOMAIN_COMPONENT));
        setLocality(extractFromX500Name(name, LOCALITY));
        setOrganisation(extractFromX500Name(name, ORGANISATION));
        setOrganisationalUnit(extractFromX500Name(name, ORGANISATIONAL_UNIT));
        setState(extractFromX500Name(name, STATE));
    }

    /**
     * Create a new {@link X500PrincipalBuilder} instance.
     *
     * @return X500Principal the principal
     *
     * @throws IllegalStateException If no attributes were specified or if the
     *                               commonname is missing or if an error
     *                               occurred.
     */
    public X500Principal build() {
        if (attributes.isEmpty()) {
            throw new IllegalStateException("No attributes specified");
        }
        if (!attributes.containsKey(COMMON_NAME)) {
            throw new IllegalStateException("Common Name not specified");
        }

        final X500NameBuilder builder = new X500NameBuilder();
        for (ASN1ObjectIdentifier key : ORDER) {
            final ASN1Primitive value = attributes.get(key);
            if (value != null) {
                builder.addRDN(key, value);
            }
        }
        try {
            return new X500Principal(builder.build().getEncoded());
        } catch (IOException exception) {
            throw new IllegalStateException("I/O error generating principal", exception);
        }
    }

    /**
     * Specifiy the <em>common name</em>.
     *
     * @param commonName names of an object. Each name is one value of this
     *                   multi-valued attribute. If the object corresponds to a
     *                   person, it is typically the person's full name.
     *
     * @return this X500PrincipalBuilder
     */
    public X500PrincipalBuilder setCommonName(String commonName) {
        if (commonName == null || commonName.trim().isEmpty()) {
            attributes.remove(COMMON_NAME);
        } else {
            attributes.put(COMMON_NAME, toDERUTF8String(commonName, 64));
        }
        return this;
    }

    /**
     * Specifiy the <em>uid</em>.
     *
     * @param uid computer system login names associated with the object. Each
     *            name is one value of this multi-valued attribute.
     *
     * @return this X500PrincipalBuilder
     */
    public X500PrincipalBuilder setUID(String uid) {
        if (uid == null || uid.trim().isEmpty()) {
            attributes.remove(UID);
        } else {
            attributes.put(UID, toDERUTF8String(uid, 64));
        }
        return this;
    }

    /**
     * Specifiy the <em>country</em>.
     *
     * @param country <em>StringType(SIZE(2))</em> a two-letter ISO 3166
     *                [ISO3166] country code.
     *
     * @return this X500PrincipalBuilder
     */
    public X500PrincipalBuilder setCountry(String country) {
        if (country == null || country.trim().isEmpty()) {
            attributes.remove(COUNTRY);
        } else {
            if (country.length() == 0) {
                throw new IllegalArgumentException("Empty country");
            }
            if (country.length() != 2) {
                throw new IllegalArgumentException("Country must be 2 characters long");
            }
            attributes.put(COUNTRY, new DERPrintableString(country, true));
        }
        return this;
    }

    /**
     * Specifiy the <em>state</em>.
     *
     * @param state <em>StringType(SIZE(1..64))</em> the full names of states or
     *              provinces. Each name is one value of this multi-valued
     *              attribute.
     *
     * @return this X500PrincipalBuilder
     */
    public X500PrincipalBuilder setState(String state) {
        if (state == null || state.trim().isEmpty()) {
            attributes.remove(STATE);
        } else {
            attributes.put(STATE, toDERUTF8String(state, 64));
        }
        return this;
    }

    /**
     * Specifiy the <em>locality</em>.
     *
     * @param locality <em>StringType(SIZE(1..64))</em> names of a locality or
     *                 place, such as a city, county, or other geographic
     *                 region. Each name is one value of this multi-valued
     *                 attribute.
     *
     * @return this X500PrincipalBuilder
     */
    public X500PrincipalBuilder setLocality(String locality) {
        if (locality == null || locality.trim().isEmpty()) {
            attributes.remove(LOCALITY);
        } else {
            attributes.put(LOCALITY, toDERUTF8String(locality, 64));
        }
        return this;
    }

    /**
     * Specifiy the <em>organisation</em>.
     *
     * @param organisation <em>StringType(SIZE(1..64))</em> names of an
     *                     organization. Each name is one value of this
     *                     multi-valued attribute.
     *
     * @return this X500PrincipalBuilder
     */
    public X500PrincipalBuilder setOrganisation(String organisation) {
        if (organisation == null || organisation.trim().isEmpty()) {
            attributes.remove(ORGANISATION);
        } else {
            attributes.put(ORGANISATION, toDERUTF8String(organisation, 64));
        }
        return this;
    }

    /**
     *
     * @param domainComponent <p>
     * a string holding one component, a label, of a DNS domain name
     * [RFC1034][RFC2181] naming a host [RFC1123]. That is, a value of this
     * attribute is a string of ASCII characters adhering to the following ABNF
     * [RFC4234]:
     * <table>
     * <caption>ABNF [RFC4234]</caption>
     * <tr><td>label = (ALPHA / DIGIT) [*61(ALPHA / DIGIT / HYPHEN) (ALPHA /
     * DIGIT)]</td></tr>
     * <tr><td>ALPHA = %x41-5A / %x61-7A ; "A"-"Z" / "a"-"z"</td></tr>
     * <tr><td>DIGIT = %x30-39 ; "0"-"9"</td></tr>
     * <tr><td>HYPHEN = %x2D ; hyphen ("-")</td></tr>
     * </table>
     * <p>
     * The encoding of IA5String for use in LDAP is simply the characters of the
     * ASCII label. The equality matching rule is case insensitive, as is
     * today's DNS. (Source: RFC 2247 [RFC2247] and RFC 1274 [RFC 1274])
     *
     * @return this X500PrincipalBuilder
     */
    public X500PrincipalBuilder setDomainComponent(String domainComponent) {
        if (domainComponent == null) {
            attributes.remove(DOMAIN_COMPONENT);
        } else {
            attributes.put(DOMAIN_COMPONENT, toDERUTF8String(domainComponent, 64));
        }
        return this;
    }

    /**
     * Specifiy the <em>organisational unit</em>.
     *
     * @param organisationalUnit <em>StringType(SIZE(1..64))</em> the names of
     *                           an organizational unit. Each name is one value
     *                           of this multi-valued attribute.
     *
     * @return this X500PrincipalBuilder
     */
    public X500PrincipalBuilder setOrganisationalUnit(String organisationalUnit) {
        if (organisationalUnit == null || organisationalUnit.trim().isEmpty()) {
            attributes.remove(ORGANISATIONAL_UNIT);
        } else {
            attributes.put(ORGANISATIONAL_UNIT, toDERUTF8String(organisationalUnit, 64));
        }
        return this;
    }

    /**
     * Specifiy the <em>email address</em>.
     *
     * @param emailAddress <em>StringType(SIZE(1..64))</em> OID
     *                     1.2.840.113549.1.9.1 - IA5String
     *
     * @return this X500PrincipalBuilder
     */
    public X500PrincipalBuilder setEmailAddress(String emailAddress) {
        if (emailAddress == null || emailAddress.trim().isEmpty()) {
            attributes.remove(EMAIL_ADDRESS);
        } else {
            if (emailAddress.length() == 0) {
                throw new IllegalArgumentException("Empty value");
            }
            if (emailAddress.length() > 128) {
                throw new IllegalArgumentException("Value too long (max=128)");
            }
            attributes.put(EMAIL_ADDRESS, new DERIA5String(emailAddress, true));
        }
        return this;
    }

    private DERUTF8String toDERUTF8String(String string, int maxLength) {
        if (string == null) {
            throw new NullPointerException("Null value");
        }
        if (string.length() == 0) {
            throw new IllegalArgumentException("Empty value");
        }
        if (string.length() > maxLength) {
            throw new IllegalArgumentException("Value too long (max=" + maxLength + ")");
        }
        return new DERUTF8String(string);
    }
}

