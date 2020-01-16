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

/**
 *
 */
public class CertificateParameters {

    private final int keySize;

    private final String commonName;
    
    private final String countryCode;
    
    private final String locality;
    
    private final String organisation;
    
    private final String organisationalUnit;
    
    private final String state;
    
    private final String mailAddress;
    
    private final String uid;
    
    private final int validityDuration;
    
    private final String alternativeName;

    public CertificateParameters(int keySize, String commonName, String countryCode, String locality, String organisation, String organisationalUnit, String state, String mailAddress, String uid, String alternativeName, int validityDuration) {
        this.validityDuration = validityDuration;
        this.keySize = keySize;
        this.commonName = commonName;
        this.countryCode = countryCode;
        this.locality = locality;
        this.organisation = organisation;
        this.organisationalUnit = organisationalUnit;
        this.state = state;
        this.mailAddress = mailAddress;
        this.uid = uid;
        this.alternativeName = alternativeName;
    }

    public String getAlternativeName() {
        return alternativeName;
    }

    public int getValidityDuration() {
        return validityDuration;
    }

    
    public String getCommonName() {
        return commonName;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public String getLocality() {
        return locality;
    }

    public String getOrganisation() {
        return organisation;
    }

    public String getOrganisationalUnit() {
        return organisationalUnit;
    }

    public String getState() {
        return state;
    }

    public String getMailAddress() {
        return mailAddress;
    }

    public String getUid() {
        return uid;
    }
    
    public int getKeySize() {
        return keySize;
    }
    
    
}
