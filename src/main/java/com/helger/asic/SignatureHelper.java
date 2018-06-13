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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.WillClose;
import javax.annotation.WillNotClose;

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

import com.helger.commons.base64.Base64;
import com.helger.commons.collection.impl.CommonsArrayList;
import com.helger.commons.io.stream.StreamHelper;
import com.helger.security.keystore.EKeyStoreType;

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

  private final Provider m_aProvider;
  private final JcaDigestCalculatorProviderBuilder m_aJcaDigestCalculatorProviderBuilder;
  private X509Certificate m_aX509Certificate;
  private Certificate [] m_aCertificateChain;
  private KeyPair m_aKeyPair;
  private JcaContentSignerBuilder m_aJcaContentSignerBuilder;

  /**
   * Loads the keystore and obtains the private key, the public key and the
   * associated certificate
   *
   * @param aKeyStoreFile
   *        file holding the JKS keystore.
   * @param sKeyStorePassword
   *        password of the key store itself
   * @param sKeyPassword
   *        password protecting the private key
   * @throws IOException
   *         on IO error
   */
  public SignatureHelper (@Nonnull final File aKeyStoreFile,
                          @Nonnull final String sKeyStorePassword,
                          @Nonnull final String sKeyPassword) throws IOException
  {
    this (aKeyStoreFile, sKeyStorePassword, null, sKeyPassword);
  }

  /**
   * Loads the keystore and obtains the private key, the public key and the
   * associated certificate referenced by the alias.
   *
   * @param aKeyStoreFile
   *        file holding the JKS keystore.
   * @param sKeyStorePassword
   *        password of the key store itself
   * @param sKeyAlias
   *        the alias referencing the private and public key pair.
   * @param sKeyPassword
   *        password protecting the private key
   * @throws IOException
   *         on IO error
   */
  public SignatureHelper (@Nonnull final File aKeyStoreFile,
                          @Nonnull final String sKeyStorePassword,
                          @Nullable final String sKeyAlias,
                          @Nonnull final String sKeyPassword) throws IOException
  {
    this (BCHelper.getProvider ());
    try (final InputStream aIS = Files.newInputStream (aKeyStoreFile.toPath ()))
    {
      final KeyStore aKS = loadKeyStore (EKeyStoreType.JKS, aIS, sKeyStorePassword);
      loadCertificate (aKS, sKeyAlias, sKeyPassword);
    }
  }

  /**
   * Loading keystore and fetching key
   *
   * @param aIS
   *        Stream for keystore
   * @param sKeyStorePassword
   *        Password to open keystore
   * @param sKeyAlias
   *        Key alias, uses first key if set to null
   * @param sKeyPassword
   *        Key password
   */
  public SignatureHelper (@Nonnull @WillClose final InputStream aIS,
                          @Nonnull final String sKeyStorePassword,
                          @Nullable final String sKeyAlias,
                          @Nonnull final String sKeyPassword)
  {
    this (BCHelper.getProvider ());
    try
    {
      loadCertificate (loadKeyStore (EKeyStoreType.JKS, aIS, sKeyStorePassword), sKeyAlias, sKeyPassword);
    }
    finally
    {
      StreamHelper.close (aIS);
    }
  }

  protected SignatureHelper (@Nullable final Provider aProvider)
  {
    m_aProvider = aProvider;

    m_aJcaDigestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder ();
    if (aProvider != null)
      m_aJcaDigestCalculatorProviderBuilder.setProvider (aProvider);
  }

  protected KeyStore loadKeyStore (@Nonnull final EKeyStoreType eKSType,
                                   @Nonnull @WillNotClose final InputStream aIS,
                                   @Nonnull final String sKeyStorePassword)
  {
    try
    {
      final KeyStore keyStore = eKSType.getKeyStore ();
      keyStore.load (aIS, sKeyStorePassword.toCharArray ());
      return keyStore;
    }
    catch (final KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e)
    {
      throw new IllegalStateException ("Load keystore; " + e.getMessage (), e);
    }
  }

  protected void loadCertificate (@Nonnull final KeyStore aKeyStore,
                                  @Nullable final String sKeyAlias,
                                  @Nonnull final String sKeyPassword)
  {
    try
    {
      final String sRealKeyAlias = sKeyAlias != null ? sKeyAlias : aKeyStore.aliases ().nextElement ();
      m_aX509Certificate = (X509Certificate) aKeyStore.getCertificate (sRealKeyAlias);
      if (m_aX509Certificate == null)
        throw new IllegalStateException ("Failed to resolve alias '" + sRealKeyAlias + "' in keystore!");

      m_aCertificateChain = aKeyStore.getCertificateChain (sRealKeyAlias);

      final Key aKey = aKeyStore.getKey (sRealKeyAlias, sKeyPassword.toCharArray ());
      final PrivateKey aPrivateKey = (PrivateKey) aKey;

      m_aKeyPair = new KeyPair (m_aX509Certificate.getPublicKey (), aPrivateKey);

      m_aJcaContentSignerBuilder = new JcaContentSignerBuilder ("SHA1with" + aPrivateKey.getAlgorithm ());
      if (m_aProvider != null)
        m_aJcaContentSignerBuilder.setProvider (m_aProvider);
    }
    catch (final KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e)
    {
      throw new IllegalStateException ("Unable to retrieve private key from keystore: " + e.getMessage (), e);
    }
  }

  /**
   * Sign content
   *
   * @param aData
   *        Content to be signed
   * @return Signature
   */
  byte [] signData (@Nonnull final byte [] aData)
  {
    try
    {
      final DigestCalculatorProvider aDigestCalculatorProvider = m_aJcaDigestCalculatorProviderBuilder.build ();
      final ContentSigner aContentSigner = m_aJcaContentSignerBuilder.build (m_aKeyPair.getPrivate ());
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

  X509Certificate getX509Certificate ()
  {
    return m_aX509Certificate;
  }

  Certificate [] getCertificateChain ()
  {
    return m_aCertificateChain;
  }
}
