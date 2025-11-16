/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2025 Philip Helger (www.helger.com)
 * philip[at]helger[dot]com
 *
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/
 */
package com.helger.asic;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1EncodableVector;
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
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.base.codec.base64.Base64;
import com.helger.base.enforce.ValueEnforcer;
import com.helger.bc.PBCProvider;
import com.helger.collection.commons.CommonsArrayList;
import com.helger.security.keystore.IKeyStoreType;
import com.helger.security.keystore.KeyStoreHelper;
import com.helger.security.keystore.LoadedKey;
import com.helger.security.keystore.LoadedKeyStore;
import com.helger.text.util.TextHelper;

/**
 * Helper class to assist when creating a signature.
 * <p>
 * Not thread safe
 *
 * @author steinar Date: 11.07.15 Time: 22.53
 */
public class SignatureHelper
{
  private static final Logger LOGGER = LoggerFactory.getLogger (SignatureHelper.class);

  private final X509Certificate m_aX509Certificate;
  private final Certificate [] m_aCertificateChain;
  private final KeyPair m_aKeyPair;

  /**
   * Loads the keystore and obtains the private key, the public key and the associated certificate
   * referenced by the alias.
   *
   * @param aKeyStoreType
   *        Key store type.
   * @param sKeyStorePath
   *        Path to keystore.
   * @param aKeyStorePassword
   *        password of the key store itself
   * @param sKeyAlias
   *        the alias referencing the private and public key pair.
   * @param aKeyPassword
   *        password protecting the private key
   * @since 3.0.1
   */
  public SignatureHelper (@NonNull final IKeyStoreType aKeyStoreType,
                          @NonNull final String sKeyStorePath,
                          @NonNull final char [] aKeyStorePassword,
                          @NonNull final String sKeyAlias,
                          @NonNull final char [] aKeyPassword)
  {
    ValueEnforcer.notNull (aKeyStoreType, "KeyStoreType");
    ValueEnforcer.notNull (sKeyStorePath, "KeyStorePath");
    ValueEnforcer.notNull (aKeyStorePassword, "KeyStorePassword");
    ValueEnforcer.notNull (sKeyAlias, "KeyAlias");
    ValueEnforcer.notNull (aKeyPassword, "KeyPassword");

    // Load key store
    final LoadedKeyStore aLKS = KeyStoreHelper.loadKeyStore (aKeyStoreType, sKeyStorePath, aKeyStorePassword);
    if (aLKS.isFailure ())
      throw new IllegalStateException (aLKS.getErrorText (TextHelper.EN));

    // Load key
    final LoadedKey <KeyStore.PrivateKeyEntry> aLK = KeyStoreHelper.loadPrivateKey (aLKS.getKeyStore (),
                                                                                    sKeyStorePath,
                                                                                    sKeyAlias,
                                                                                    aKeyPassword);
    if (aLK.isFailure ())
      throw new IllegalStateException (aLK.getErrorText (TextHelper.EN));
    m_aCertificateChain = aLK.getKeyEntry ().getCertificateChain ();
    m_aX509Certificate = (X509Certificate) aLK.getKeyEntry ().getCertificate ();
    m_aKeyPair = new KeyPair (m_aX509Certificate.getPublicKey (), aLK.getKeyEntry ().getPrivateKey ());
  }

  /**
   * Sign content using CMS.
   *
   * @param aData
   *        Content to be signed. May not be <code>null</code>.
   * @param eMDAlgo
   *        Message Digest Algorithm
   * @return Signature
   */
  protected final byte [] signData (@NonNull final byte [] aData, @NonNull final EMessageDigestAlgorithm eMDAlgo)
  {
    try
    {
      final Provider p = PBCProvider.getProvider ();
      final DigestCalculatorProvider aDigestCalculatorProvider = new JcaDigestCalculatorProviderBuilder ().setProvider (p)
                                                                                                          .build ();
      final JcaContentSignerBuilder aJcaContentSignerBuilder = new JcaContentSignerBuilder (eMDAlgo.getContentSignerAlgorithm () +
                                                                                            "with" +
                                                                                            m_aKeyPair.getPrivate ()
                                                                                                      .getAlgorithm ()).setProvider (p);

      // Calculate signing certificate digest
      final MessageDigest aMD = MessageDigest.getInstance (eMDAlgo.getMessageDigestAlgorithm ());
      aMD.update (m_aX509Certificate.getEncoded ());
      final byte [] aCertDigest = aMD.digest ();

      // Create IssuerSerial object
      final X500Name aIssuerX500Name = new X509CertificateHolder (m_aX509Certificate.getEncoded ()).getIssuer ();
      final GeneralName aGeneralName = new GeneralName (aIssuerX500Name);
      final GeneralNames aGeneralNames = new GeneralNames (aGeneralName);
      final BigInteger aGerialNumber = m_aX509Certificate.getSerialNumber ();
      final IssuerSerial aIssuerSerial = new IssuerSerial (aGeneralNames, aGerialNumber);

      // Use IssuerSerial and the digest to create a SigningCertificate
      // Attribute, v1 for SHA1 v2 for the rest
      final Attribute aAttribute;
      if (eMDAlgo.isSHA1 ())
      {
        final ESSCertID aCertID = new ESSCertID (aCertDigest, aIssuerSerial);
        final SigningCertificate aSigningCertificate = new SigningCertificate (aCertID);
        aAttribute = new Attribute (PKCSObjectIdentifiers.id_aa_signingCertificate, new DERSet (aSigningCertificate));
      }
      else
      {
        final ESSCertIDv2 aCertIdv2 = new ESSCertIDv2 (new AlgorithmIdentifier (eMDAlgo.getOID (), DERNull.INSTANCE),
                                                       aCertDigest,
                                                       aIssuerSerial);
        final SigningCertificateV2 aSigningCertificateV2 = new SigningCertificateV2 (aCertIdv2);
        aAttribute = new Attribute (PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                                    new DERSet (aSigningCertificateV2));
      }

      // Add that attribute to a SignedAttributeTableGenerator
      final ASN1EncodableVector aSignedAttributes = new ASN1EncodableVector ();
      aSignedAttributes.add (aAttribute);
      final AttributeTable aAttributeTable = new AttributeTable (aSignedAttributes);
      final DefaultSignedAttributeTableGenerator aAttributeTableGenerator = new DefaultSignedAttributeTableGenerator (aAttributeTable);

      final ContentSigner aContentSigner = aJcaContentSignerBuilder.build (m_aKeyPair.getPrivate ());
      final CMSSignedDataGenerator aCMSSignedDataGenerator = new CMSSignedDataGenerator ();
      if (true)
      {
        // Add the SignedAttributeTableGenerator to the SignerInfoGenerator
        final SignerInfoGenerator aSignerInfoGenerator = new JcaSignerInfoGeneratorBuilder (aDigestCalculatorProvider).setSignedAttributeGenerator (aAttributeTableGenerator)
                                                                                                                      .build (aContentSigner,
                                                                                                                              m_aX509Certificate);
        aCMSSignedDataGenerator.addSignerInfoGenerator (aSignerInfoGenerator);

        // Put the provided certificate chain into the signature
        aCMSSignedDataGenerator.addCertificates (new JcaCertStore (new CommonsArrayList <> (getCertificateChain ())));
      }
      else
      {
        // Old code
        final SignerInfoGenerator aSignerInfoGenerator = new JcaSignerInfoGeneratorBuilder (aDigestCalculatorProvider).build (aContentSigner,
                                                                                                                              m_aX509Certificate);

        aCMSSignedDataGenerator.addSignerInfoGenerator (aSignerInfoGenerator);
        aCMSSignedDataGenerator.addCertificates (new JcaCertStore (new CommonsArrayList <> (m_aX509Certificate)));
      }
      final CMSSignedData aCMSSignedData = aCMSSignedDataGenerator.generate (new CMSProcessableByteArray (aData),
                                                                             false);

      if (LOGGER.isDebugEnabled ())
        LOGGER.debug (Base64.encodeBytes (aCMSSignedData.getEncoded ()));
      return aCMSSignedData.getEncoded ();
    }
    catch (final Exception ex)
    {
      throw new IllegalStateException ("Unable to sign with " + eMDAlgo, ex);
    }
  }

  @NonNull
  protected final X509Certificate getX509Certificate ()
  {
    return m_aX509Certificate;
  }

  @NonNull
  protected final Certificate [] getCertificateChain ()
  {
    return m_aCertificateChain;
  }

  @NonNull
  protected final KeyPair getKeyPair ()
  {
    return m_aKeyPair;
  }
}
