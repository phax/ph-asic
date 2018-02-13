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
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.WillClose;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.base64.Base64;
import com.helger.commons.io.stream.StreamHelper;

/**
 * Helper class to assist when creating a signature.
 * <p>
 * Not thread safe
 *
 * @author steinar Date: 11.07.15 Time: 22.53
 */
public class SignatureHelper
{
  private static final Logger logger = LoggerFactory.getLogger (SignatureHelper.class);

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
   * @param keyStoreFile
   *        file holding the JKS keystore.
   * @param keyStorePassword
   *        password of the key store itself
   * @param keyPassword
   *        password protecting the private key
   * @throws IOException
   *         on IO error
   */
  public SignatureHelper (final File keyStoreFile,
                          final String keyStorePassword,
                          final String keyPassword) throws IOException
  {
    this (keyStoreFile, keyStorePassword, null, keyPassword);
  }

  /**
   * Loads the keystore and obtains the private key, the public key and the
   * associated certificate referenced by the alias.
   *
   * @param keyStoreFile
   *        file holding the JKS keystore.
   * @param keyStorePassword
   *        password of the key store itself
   * @param keyAlias
   *        the alias referencing the private and public key pair.
   * @param keyPassword
   *        password protecting the private key
   * @throws IOException
   *         on IO error
   */
  public SignatureHelper (@Nonnull final File keyStoreFile,
                          @Nonnull final String keyStorePassword,
                          @Nullable final String keyAlias,
                          @Nonnull final String keyPassword) throws IOException
  {
    this (BCHelper.getProvider ());
    try (final InputStream inputStream = Files.newInputStream (keyStoreFile.toPath ()))
    {
      final KeyStore aKS = loadKeyStore (inputStream, keyStorePassword);
      loadCertificate (aKS, keyAlias, keyPassword);
    }
  }

  /**
   * Loading keystore and fetching key
   *
   * @param keyStoreStream
   *        Stream for keystore
   * @param keyStorePassword
   *        Password to open keystore
   * @param keyAlias
   *        Key alias, uses first key if set to null
   * @param keyPassword
   *        Key password
   */
  public SignatureHelper (@WillClose final InputStream keyStoreStream,
                          final String keyStorePassword,
                          final String keyAlias,
                          final String keyPassword)
  {
    this (BCHelper.getProvider ());
    try
    {
      loadCertificate (loadKeyStore (keyStoreStream, keyStorePassword), keyAlias, keyPassword);
    }
    finally
    {
      StreamHelper.close (keyStoreStream);
    }
  }

  protected SignatureHelper (@Nullable final Provider aProvider)
  {
    m_aProvider = aProvider;

    m_aJcaDigestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder ();
    if (aProvider != null)
      m_aJcaDigestCalculatorProviderBuilder.setProvider (aProvider);
  }

  protected KeyStore loadKeyStore (@Nonnull final InputStream keyStoreStream, @Nonnull final String keyStorePassword)
  {
    try
    {
      final KeyStore keyStore = KeyStore.getInstance ("JKS");
      keyStore.load (keyStoreStream, keyStorePassword.toCharArray ()); // TODO:
                                                                       // find
                                                                       // password
                                                                       // of
                                                                       // keystore

      return keyStore;
    }
    catch (final Exception e)
    {
      throw new IllegalStateException (String.format ("Load keystore; %s", e.getMessage ()), e);
    }
  }

  protected void loadCertificate (@Nonnull final KeyStore keyStore,
                                  @Nullable final String keyAlias,
                                  @Nonnull final String keyPassword)
  {
    try
    {
      final String sKeyAlias = keyAlias != null ? keyAlias : keyStore.aliases ().nextElement ();
      m_aX509Certificate = (X509Certificate) keyStore.getCertificate (sKeyAlias);

      m_aCertificateChain = keyStore.getCertificateChain (sKeyAlias);

      final Key key = keyStore.getKey (sKeyAlias, keyPassword.toCharArray ());
      final PrivateKey privateKey = (PrivateKey) key;

      m_aKeyPair = new KeyPair (m_aX509Certificate.getPublicKey (), privateKey);

      m_aJcaContentSignerBuilder = new JcaContentSignerBuilder (String.format ("SHA1with%s",
                                                                               privateKey.getAlgorithm ()));
      if (m_aProvider != null)
        m_aJcaContentSignerBuilder.setProvider (m_aProvider);
    }
    catch (final Exception e)
    {
      throw new IllegalStateException (String.format ("Unable to retrieve private key from keystore: %s",
                                                      e.getMessage ()),
                                       e);
    }
  }

  /**
   * Sign content
   *
   * @param data
   *        Content to be signed
   * @return Signature
   */
  byte [] signData (final byte [] data)
  {
    try
    {
      final DigestCalculatorProvider digestCalculatorProvider = m_aJcaDigestCalculatorProviderBuilder.build ();
      final ContentSigner contentSigner = m_aJcaContentSignerBuilder.build (m_aKeyPair.getPrivate ());
      final SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder (digestCalculatorProvider).build (contentSigner,
                                                                                                                          m_aX509Certificate);

      final CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator ();
      cmsSignedDataGenerator.addSignerInfoGenerator (signerInfoGenerator);
      cmsSignedDataGenerator.addCertificates (new JcaCertStore (Collections.singletonList (m_aX509Certificate)));
      final CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate (new CMSProcessableByteArray (data), false);

      logger.debug (Base64.encodeBytes (cmsSignedData.getEncoded ()));
      return cmsSignedData.getEncoded ();
    }
    catch (final Exception e)
    {
      throw new IllegalStateException (String.format ("Unable to sign: %s", e.getMessage ()), e);
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
