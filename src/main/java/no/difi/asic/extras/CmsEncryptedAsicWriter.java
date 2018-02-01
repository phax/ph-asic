package no.difi.asic.extras;

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

import com.helger.commons.io.stream.StreamHelper;

import no.difi.asic.AsicUtils;
import no.difi.asic.AsicWriter;
import no.difi.asic.MimeType;
import no.difi.asic.SignatureHelper;

/**
 * Wrapper to seamlessly encode specific files.
 */
public class CmsEncryptedAsicWriter extends CmsEncryptedAsicAbstract implements AsicWriter
{

  private final AsicWriter asicWriter;
  private final X509Certificate certificate;
  private final ASN1ObjectIdentifier cmsAlgorithm;

  private final Set <String> entryNeames = new TreeSet <> ();

  public CmsEncryptedAsicWriter (final AsicWriter asicWriter, final X509Certificate certificate)
  {
    this (asicWriter, certificate, CMSAlgorithm.AES256_GCM);
  }

  public CmsEncryptedAsicWriter (final AsicWriter asicWriter,
                                 final X509Certificate certificate,
                                 final ASN1ObjectIdentifier cmsAlgorithm)
  {
    this.asicWriter = asicWriter;
    this.certificate = certificate;
    this.cmsAlgorithm = cmsAlgorithm;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public AsicWriter add (final File file) throws IOException
  {
    return add (file.toPath ());
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public AsicWriter add (final File file, final String entryName) throws IOException
  {
    return add (file.toPath (), entryName);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public AsicWriter add (final Path path) throws IOException
  {
    return add (path, path.toFile ().getName ());
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public AsicWriter add (final Path path, final String entryName) throws IOException
  {
    try (InputStream inputStream = Files.newInputStream (path))
    {
      add (inputStream, entryName);
    }
    return this;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public AsicWriter add (final InputStream inputStream, final String filename) throws IOException
  {
    return add (inputStream, filename, AsicUtils.detectMime (filename));
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public AsicWriter add (final File file, final String entryName, final MimeType mimeType) throws IOException
  {
    return add (file.toPath (), entryName, mimeType);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public AsicWriter add (final Path path, final String entryName, final MimeType mimeType) throws IOException
  {
    try (InputStream inputStream = Files.newInputStream (path))
    {
      add (inputStream, entryName, mimeType);
    }
    return this;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public AsicWriter add (final InputStream inputStream,
                         final String filename,
                         final MimeType mimeType) throws IOException
  {
    return asicWriter.add (inputStream, filename, mimeType);
  }

  public AsicWriter addEncrypted (final File file) throws IOException
  {
    return addEncrypted (file.toPath ());
  }

  public AsicWriter addEncrypted (final File file, final String entryName) throws IOException
  {
    return addEncrypted (file.toPath (), entryName);
  }

  public AsicWriter addEncrypted (final Path path) throws IOException
  {
    return addEncrypted (path, path.toFile ().getName ());
  }

  public AsicWriter addEncrypted (final Path path, final String entryName) throws IOException
  {
    try (InputStream inputStream = Files.newInputStream (path))
    {
      addEncrypted (inputStream, entryName);
    }
    return this;
  }

  public AsicWriter addEncrypted (final InputStream inputStream, final String filename) throws IOException
  {
    return addEncrypted (inputStream, filename, AsicUtils.detectMime (filename));
  }

  public AsicWriter addEncrypted (final File file, final String entryName, final MimeType mimeType) throws IOException
  {
    return addEncrypted (file.toPath (), entryName, mimeType);
  }

  public AsicWriter addEncrypted (final Path path, final String entryName, final MimeType mimeType) throws IOException
  {
    try (InputStream inputStream = Files.newInputStream (path))
    {
      addEncrypted (inputStream, entryName, mimeType);
    }
    return this;
  }

  public AsicWriter addEncrypted (final InputStream inputStream,
                                  final String filename,
                                  final MimeType mimeType) throws IOException
  {
    try
    {
      final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream ();
      StreamHelper.copyInputStreamToOutputStream (inputStream, byteArrayOutputStream);

      final CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator ();
      cmsEnvelopedDataGenerator.addRecipientInfoGenerator (new JceKeyTransRecipientInfoGenerator (certificate).setProvider (BC));
      final CMSEnvelopedData data = cmsEnvelopedDataGenerator.generate (new CMSProcessableByteArray (byteArrayOutputStream.toByteArray ()),
                                                                        new JceCMSContentEncryptorBuilder (cmsAlgorithm).setProvider (BC)
                                                                                                                        .build ());

      this.entryNeames.add (filename);

      return asicWriter.add (new ByteArrayInputStream (data.getEncoded ()), filename + ".p7m", mimeType);
    }
    catch (final Exception e)
    {
      throw new IOException (e.getMessage (), e);
    }
  }

  @Override
  public AsicWriter setRootEntryName (String name)
  {
    if (this.entryNeames.contains (name))
      name = String.format ("%s.p7m", name);

    return asicWriter.setRootEntryName (name);
  }

  @Override
  public AsicWriter sign (final File keyStoreFile,
                          final String keyStorePassword,
                          final String keyPassword) throws IOException
  {
    return asicWriter.sign (keyStoreFile, keyStorePassword, keyPassword);
  }

  @Override
  public AsicWriter sign (final File keyStoreFile,
                          final String keyStorePassword,
                          final String keyAlias,
                          final String keyPassword) throws IOException
  {
    return asicWriter.sign (keyStoreFile, keyStorePassword, keyAlias, keyPassword);
  }

  @Override
  public AsicWriter sign (final SignatureHelper signatureHelper) throws IOException
  {
    return asicWriter.sign (signatureHelper);
  }
}
