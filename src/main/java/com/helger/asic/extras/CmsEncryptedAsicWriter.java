package com.helger.asic.extras;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.TreeSet;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;

import com.helger.asic.AsicUtils;
import com.helger.asic.IAsicWriter;
import com.helger.asic.MimeType;
import com.helger.asic.SignatureHelper;

/**
 * Wrapper to seamlessly encode specific files.
 */
public class CmsEncryptedAsicWriter extends CmsEncryptedAsicAbstract implements IAsicWriter
{
  private final IAsicWriter m_aAsicWriter;
  private final X509Certificate m_aCertificate;
  private final ASN1ObjectIdentifier m_aCmsAlgorithm;

  private final Set <String> m_aEntryNames = new TreeSet <> ();

  public CmsEncryptedAsicWriter (final IAsicWriter asicWriter, final X509Certificate certificate)
  {
    this (asicWriter, certificate, CMSAlgorithm.AES256_GCM);
  }

  public CmsEncryptedAsicWriter (final IAsicWriter asicWriter,
                                 final X509Certificate certificate,
                                 final ASN1ObjectIdentifier cmsAlgorithm)
  {
    m_aAsicWriter = asicWriter;
    m_aCertificate = certificate;
    m_aCmsAlgorithm = cmsAlgorithm;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public IAsicWriter add (final File file) throws IOException
  {
    return add (file.toPath ());
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public IAsicWriter add (final InputStream inputStream,
                          final String filename,
                          final MimeType mimeType) throws IOException
  {
    return m_aAsicWriter.add (inputStream, filename, mimeType);
  }

  public IAsicWriter addEncrypted (final File file) throws IOException
  {
    return addEncrypted (file.toPath ());
  }

  public IAsicWriter addEncrypted (final File file, final String entryName) throws IOException
  {
    return addEncrypted (file.toPath (), entryName);
  }

  public IAsicWriter addEncrypted (final Path path) throws IOException
  {
    return addEncrypted (path, path.toFile ().getName ());
  }

  public IAsicWriter addEncrypted (final Path path, final String entryName) throws IOException
  {
    try (InputStream inputStream = Files.newInputStream (path))
    {
      addEncrypted (inputStream, entryName);
    }
    return this;
  }

  public IAsicWriter addEncrypted (final InputStream inputStream, final String filename) throws IOException
  {
    return addEncrypted (inputStream, filename, AsicUtils.detectMime (filename));
  }

  public IAsicWriter addEncrypted (final File file, final String entryName, final MimeType mimeType) throws IOException
  {
    return addEncrypted (file.toPath (), entryName, mimeType);
  }

  public IAsicWriter addEncrypted (final Path path, final String entryName, final MimeType mimeType) throws IOException
  {
    try (InputStream inputStream = Files.newInputStream (path))
    {
      addEncrypted (inputStream, entryName, mimeType);
    }
    return this;
  }

  public IAsicWriter addEncrypted (final InputStream inputStream,
                                   final String filename,
                                   final MimeType mimeType) throws IOException
  {
    try
    {
      final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream ();
      AsicUtils.copyStream (inputStream, byteArrayOutputStream);

      final CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator ();
      cmsEnvelopedDataGenerator.addRecipientInfoGenerator (new JceKeyTransRecipientInfoGenerator (m_aCertificate).setProvider (BC));
      final CMSEnvelopedData data = cmsEnvelopedDataGenerator.generate (new CMSProcessableByteArray (byteArrayOutputStream.toByteArray ()),
                                                                        new JceCMSContentEncryptorBuilder (m_aCmsAlgorithm).setProvider (BC)
                                                                                                                           .build ());

      this.m_aEntryNames.add (filename);

      return m_aAsicWriter.add (new ByteArrayInputStream (data.getEncoded ()), filename + ".p7m", mimeType);
    }
    catch (final Exception e)
    {
      throw new IOException (e.getMessage (), e);
    }
  }

  @Override
  public IAsicWriter setRootEntryName (String name)
  {
    if (this.m_aEntryNames.contains (name))
      name = String.format ("%s.p7m", name);

    return m_aAsicWriter.setRootEntryName (name);
  }

  @Override
  public IAsicWriter sign (final File keyStoreFile,
                           final String keyStorePassword,
                           final String keyPassword) throws IOException
  {
    return m_aAsicWriter.sign (keyStoreFile, keyStorePassword, keyPassword);
  }

  @Override
  public IAsicWriter sign (final File keyStoreFile,
                           final String keyStorePassword,
                           final String keyAlias,
                           final String keyPassword) throws IOException
  {
    return m_aAsicWriter.sign (keyStoreFile, keyStorePassword, keyAlias, keyPassword);
  }

  @Override
  public IAsicWriter sign (final SignatureHelper signatureHelper) throws IOException
  {
    return m_aAsicWriter.sign (signatureHelper);
  }
}
