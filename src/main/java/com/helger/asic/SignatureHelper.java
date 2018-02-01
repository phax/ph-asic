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

  protected final Provider provider;

  protected final JcaDigestCalculatorProviderBuilder jcaDigestCalculatorProviderBuilder;

  protected X509Certificate x509Certificate;

  protected java.security.cert.Certificate [] certificateChain;

  protected KeyPair keyPair;

  protected JcaContentSignerBuilder jcaContentSignerBuilder;

  /**
   * Loads the keystore and obtains the private key, the public key and the
   * associated certificate
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
   */
  public SignatureHelper (final File keyStoreFile,
                          final String keyStorePassword,
                          final String keyAlias,
                          final String keyPassword) throws IOException
  {
    this (BCHelper.getProvider ());
    try (InputStream inputStream = Files.newInputStream (keyStoreFile.toPath ()))
    {
      loadCertificate (loadKeyStore (inputStream, keyStorePassword), keyAlias, keyPassword);
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
  public SignatureHelper (final InputStream keyStoreStream,
                          final String keyStorePassword,
                          final String keyAlias,
                          final String keyPassword)
  {
    this (BCHelper.getProvider ());
    loadCertificate (loadKeyStore (keyStoreStream, keyStorePassword), keyAlias, keyPassword);
  }

  protected SignatureHelper (final Provider provider)
  {
    this.provider = provider;

    jcaDigestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder ();
    if (provider != null)
      jcaDigestCalculatorProviderBuilder.setProvider (provider);
  }

  protected KeyStore loadKeyStore (final InputStream keyStoreStream, final String keyStorePassword)
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

  protected void loadCertificate (final KeyStore keyStore, String keyAlias, final String keyPassword)
  {
    try
    {
      if (keyAlias == null)
        keyAlias = keyStore.aliases ().nextElement ();
      x509Certificate = (X509Certificate) keyStore.getCertificate (keyAlias);

      certificateChain = keyStore.getCertificateChain (keyAlias);

      final Key key = keyStore.getKey (keyAlias, keyPassword.toCharArray ());
      final PrivateKey privateKey = (PrivateKey) key;

      keyPair = new KeyPair (x509Certificate.getPublicKey (), privateKey);

      jcaContentSignerBuilder = new JcaContentSignerBuilder (String.format ("SHA1with%s", privateKey.getAlgorithm ()));
      if (provider != null)
        jcaContentSignerBuilder.setProvider (provider);
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
      final DigestCalculatorProvider digestCalculatorProvider = jcaDigestCalculatorProviderBuilder.build ();
      final ContentSigner contentSigner = jcaContentSignerBuilder.build (keyPair.getPrivate ());
      final SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder (digestCalculatorProvider).build (contentSigner,
                                                                                                                          x509Certificate);

      final CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator ();
      cmsSignedDataGenerator.addSignerInfoGenerator (signerInfoGenerator);
      cmsSignedDataGenerator.addCertificates (new JcaCertStore (Collections.singletonList (x509Certificate)));
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
    return x509Certificate;
  }

  Certificate [] getCertificateChain ()
  {
    return certificateChain;
  }
}
