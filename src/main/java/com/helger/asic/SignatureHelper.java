/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018 Philip Helger (www.helger.com)
 * philip[at]helger[dot]com
 *
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/
 */
package com.helger.asic;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.annotation.Nonnull;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.bc.PBCProvider;
import com.helger.commons.ValueEnforcer;
import com.helger.commons.base64.Base64;
import com.helger.commons.collection.impl.CommonsArrayList;
import com.helger.commons.text.util.TextHelper;
import com.helger.security.keystore.IKeyStoreType;
import com.helger.security.keystore.KeyStoreHelper;
import com.helger.security.keystore.LoadedKey;
import com.helger.security.keystore.LoadedKeyStore;

/**
 * Helper class to assist when creating a signature.
 * <p>
 * Not thread safe
 *
 * @author steinar Date: 11.07.15 Time: 22.53
 */
public class SignatureHelper
{
  private static final Logger LOG = LoggerFactory.getLogger (SignatureHelper.class);

  private final X509Certificate m_aX509Certificate;
  private final Certificate [] m_aCertificateChain;
  private final KeyPair m_aKeyPair;

  /**
   * Loads the keystore and obtains the private key, the public key and the
   * associated certificate referenced by the alias.
   *
   * @param aKeyStoreType
   *        Key store type.
   * @param sKeyStorePath
   *        Path to keystore.
   * @param sKeyStorePassword
   *        password of the key store itself
   * @param sKeyAlias
   *        the alias referencing the private and public key pair.
   * @param sKeyPassword
   *        password protecting the private key
   */
  public SignatureHelper (@Nonnull final IKeyStoreType aKeyStoreType,
                          @Nonnull final String sKeyStorePath,
                          @Nonnull final String sKeyStorePassword,
                          @Nonnull final String sKeyAlias,
                          @Nonnull final String sKeyPassword)
  {
    ValueEnforcer.notNull (aKeyStoreType, "KeyStoreType");
    ValueEnforcer.notNull (sKeyStorePath, "KeyStorePath");
    ValueEnforcer.notNull (sKeyStorePassword, "KeyStorePassword");
    ValueEnforcer.notNull (sKeyAlias, "KeyAlias");
    ValueEnforcer.notNull (sKeyPassword, "KeyPassword");

    // Load key store
    final LoadedKeyStore aLKS = KeyStoreHelper.loadKeyStore (aKeyStoreType, sKeyStorePath, sKeyStorePassword);
    if (aLKS.isFailure ())
      throw new IllegalStateException (aLKS.getErrorText (TextHelper.EN));

    // Load key
    final LoadedKey <KeyStore.PrivateKeyEntry> aLK = KeyStoreHelper.loadPrivateKey (aLKS.getKeyStore (),
                                                                                    sKeyStorePath,
                                                                                    sKeyAlias,
                                                                                    sKeyPassword.toCharArray ());
    if (aLK.isFailure ())
      throw new IllegalStateException (aLK.getErrorText (TextHelper.EN));
    m_aCertificateChain = aLK.getKeyEntry ().getCertificateChain ();
    m_aX509Certificate = (X509Certificate) aLK.getKeyEntry ().getCertificate ();
    m_aKeyPair = new KeyPair (m_aX509Certificate.getPublicKey (), aLK.getKeyEntry ().getPrivateKey ());
  }

  /**
   * Sign content
   *
   * @param aData
   *        Content to be signed
   * @return Signature
   */
  protected final byte [] signData (@Nonnull final byte [] aData)
  {
    try
    {
      final Provider p = PBCProvider.getProvider ();
      final DigestCalculatorProvider aDigestCalculatorProvider = new JcaDigestCalculatorProviderBuilder ().setProvider (p)
                                                                                                          .build ();
      final JcaContentSignerBuilder aJcaContentSignerBuilder = new JcaContentSignerBuilder ("SHA1with" +
                                                                                            m_aKeyPair.getPrivate ()
                                                                                                      .getAlgorithm ()).setProvider (p);
      final ContentSigner aContentSigner = aJcaContentSignerBuilder.build (m_aKeyPair.getPrivate ());
      final SignerInfoGenerator aSignerInfoGenerator = new JcaSignerInfoGeneratorBuilder (aDigestCalculatorProvider).build (aContentSigner,
                                                                                                                            m_aX509Certificate);

      final CMSSignedDataGenerator aCMSSignedDataGenerator = new CMSSignedDataGenerator ();
      aCMSSignedDataGenerator.addSignerInfoGenerator (aSignerInfoGenerator);
      aCMSSignedDataGenerator.addCertificates (new JcaCertStore (new CommonsArrayList <> (m_aX509Certificate)));
      final CMSSignedData aCMSSignedData = aCMSSignedDataGenerator.generate (new CMSProcessableByteArray (aData),
                                                                             false);

      if (LOG.isDebugEnabled ())
        LOG.debug (Base64.encodeBytes (aCMSSignedData.getEncoded ()));
      return aCMSSignedData.getEncoded ();
    }
    catch (final OperatorCreationException | CertificateEncodingException | CMSException | IOException e)
    {
      throw new IllegalStateException ("Unable to sign: " + e.getMessage (), e);
    }
  }

  @Nonnull
  protected final X509Certificate getX509Certificate ()
  {
    return m_aX509Certificate;
  }

  @Nonnull
  protected final Certificate [] getCertificateChain ()
  {
    return m_aCertificateChain;
  }

  @Nonnull
  protected final KeyPair getKeyPair ()
  {
    return m_aKeyPair;
  }
}
