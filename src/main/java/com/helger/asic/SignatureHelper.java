/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2019 Philip Helger (www.helger.com)
 * philip[at]helger[dot]com
 * <p>
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/
 */
package com.helger.asic;

import com.helger.bc.PBCProvider;
import com.helger.commons.ValueEnforcer;
import com.helger.commons.base64.Base64;
import com.helger.commons.collection.impl.CommonsArrayList;
import com.helger.commons.text.util.TextHelper;
import com.helger.security.keystore.IKeyStoreType;
import com.helger.security.keystore.KeyStoreHelper;
import com.helger.security.keystore.LoadedKey;
import com.helger.security.keystore.LoadedKeyStore;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificate;

/**
 * Helper class to assist when creating a signature.
 * <p>
 * Not thread safe
 *
 * @author steinar Date: 11.07.15 Time: 22.53
 */
public class SignatureHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(SignatureHelper.class);

    private final X509Certificate m_aX509Certificate;
    private final Certificate[] m_aCertificateChain;
    private final KeyPair m_aKeyPair;

    /**
     * Loads the keystore and obtains the private key, the public key and the
     * associated certificate referenced by the alias.
     *
     * @param aKeyStoreType     Key store type.
     * @param sKeyStorePath     Path to keystore.
     * @param sKeyStorePassword password of the key store itself
     * @param sKeyAlias         the alias referencing the private and public key pair.
     * @param sKeyPassword      password protecting the private key
     */
    public SignatureHelper(@Nonnull final IKeyStoreType aKeyStoreType,
                           @Nonnull final String sKeyStorePath,
                           @Nonnull final String sKeyStorePassword,
                           @Nonnull final String sKeyAlias,
                           @Nonnull final String sKeyPassword) {
        ValueEnforcer.notNull(aKeyStoreType, "KeyStoreType");
        ValueEnforcer.notNull(sKeyStorePath, "KeyStorePath");
        ValueEnforcer.notNull(sKeyStorePassword, "KeyStorePassword");
        ValueEnforcer.notNull(sKeyAlias, "KeyAlias");
        ValueEnforcer.notNull(sKeyPassword, "KeyPassword");

        // Load key store
        final LoadedKeyStore aLKS = KeyStoreHelper.loadKeyStore(aKeyStoreType, sKeyStorePath, sKeyStorePassword);
        if (aLKS.isFailure())
            throw new IllegalStateException(aLKS.getErrorText(TextHelper.EN));

        // Load key
        final LoadedKey<KeyStore.PrivateKeyEntry> aLK = KeyStoreHelper.loadPrivateKey(aLKS.getKeyStore(),
                sKeyStorePath,
                sKeyAlias,
                sKeyPassword.toCharArray());
        if (aLK.isFailure())
            throw new IllegalStateException(aLK.getErrorText(TextHelper.EN));
        m_aCertificateChain = aLK.getKeyEntry().getCertificateChain();
        m_aX509Certificate = (X509Certificate) aLK.getKeyEntry().getCertificate();
        m_aKeyPair = new KeyPair(m_aX509Certificate.getPublicKey(), aLK.getKeyEntry().getPrivateKey());
    }

    /**
     * Sign content using CMS.
     *
     * @param aData   Content to be signed. May not be <code>null</code>.
     * @param eMDAlgo Message Digest Algorithm
     * @return Signature
     */
    protected final byte[] signData(@Nonnull final byte[] aData, @Nonnull final EMessageDigestAlgorithm eMDAlgo) {
        try {
            final Provider p = PBCProvider.getProvider();
            final DigestCalculatorProvider aDigestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(p)
                    .build();
            final JcaContentSignerBuilder aJcaContentSignerBuilder = new JcaContentSignerBuilder(eMDAlgo.getContentSignerAlgorithm() +
                    "with" +
                    m_aKeyPair.getPrivate()
                            .getAlgorithm()).setProvider(p);

            // Calculate signing certificate digest
            MessageDigest md = MessageDigest.getInstance(eMDAlgo.getMessageDigestAlgorithm());
            byte[] der = m_aX509Certificate.getEncoded();
            md.update(der);
            byte[] certDigest = md.digest();

            // Create IssuerSerial object
            final X500Name issuerX500Name = new X509CertificateHolder(m_aX509Certificate.getEncoded()).getIssuer();
            final GeneralName generalName = new GeneralName(issuerX500Name);
            final GeneralNames generalNames = new GeneralNames(generalName);
            final BigInteger serialNumber = m_aX509Certificate.getSerialNumber();
            IssuerSerial theIssuerSerial = new IssuerSerial(generalNames, serialNumber);

            // Use IssuerSerial and the digest to create a SigningCertificate Attribute, v1 for SHA1 v2 for the rest
            Attribute attribute;
            if (eMDAlgo == EMessageDigestAlgorithm.SHA1) {
                final ESSCertID essCertID = new ESSCertID(certDigest, theIssuerSerial);
                SigningCertificate signingCertificate = new SigningCertificate(essCertID);
                attribute = new Attribute(id_aa_signingCertificate, new DERSet(signingCertificate));
            } else {
                ESSCertIDv2 essCertIdv2 = new ESSCertIDv2(new AlgorithmIdentifier(
                        new ASN1ObjectIdentifier(eMDAlgo.getOid()),
                        DERNull.INSTANCE),
                        certDigest, theIssuerSerial);
                SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2(essCertIdv2);
                attribute = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(signingCertificateV2));
            }

            // Add that attribute to a SignedAttributeTableGenerator
            ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
            signedAttributes.add(attribute);
            AttributeTable attributeTable = new AttributeTable(signedAttributes);
            DefaultSignedAttributeTableGenerator attributeTableGenerator = new DefaultSignedAttributeTableGenerator(attributeTable);

            final ContentSigner aContentSigner = aJcaContentSignerBuilder.build(m_aKeyPair.getPrivate());
            final SignerInfoGenerator aSignerInfoGenerator = new JcaSignerInfoGeneratorBuilder(aDigestCalculatorProvider)
                    // Add the SignedAttributeTableGenerator to the SignerInfoGenerator
                    .setSignedAttributeGenerator(attributeTableGenerator)
                    .build(aContentSigner, m_aX509Certificate);

            final CMSSignedDataGenerator aCMSSignedDataGenerator = new CMSSignedDataGenerator();
            aCMSSignedDataGenerator.addSignerInfoGenerator(aSignerInfoGenerator);

            // Put the provided certificate chain into the signature
            aCMSSignedDataGenerator.addCertificates(new JcaCertStore(new CommonsArrayList<>(getCertificateChain())));
            final CMSSignedData aCMSSignedData = aCMSSignedDataGenerator.generate(new CMSProcessableByteArray(aData),
                    false);

            if (LOGGER.isDebugEnabled())
                LOGGER.debug(Base64.encodeBytes(aCMSSignedData.getEncoded()));
            return aCMSSignedData.getEncoded();
        } catch (final OperatorCreationException | CertificateEncodingException | CMSException | IOException | NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Unable to sign with " + eMDAlgo, ex);
        }
    }

    @Nonnull
    protected final X509Certificate getX509Certificate() {
        return m_aX509Certificate;
    }

    @Nonnull
    protected final Certificate[] getCertificateChain() {
        return m_aCertificateChain;
    }

    @Nonnull
    protected final KeyPair getKeyPair() {
        return m_aKeyPair;
    }
}
