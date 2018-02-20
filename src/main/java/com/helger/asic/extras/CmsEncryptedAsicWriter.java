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
package com.helger.asic.extras;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.TreeSet;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;

import com.helger.asic.AsicUtils;
import com.helger.asic.BCHelper;
import com.helger.asic.IAsicWriter;
import com.helger.asic.SignatureHelper;
import com.helger.commons.io.stream.NonBlockingByteArrayInputStream;
import com.helger.commons.io.stream.NonBlockingByteArrayOutputStream;
import com.helger.commons.mime.IMimeType;

/**
 * Wrapper to seamlessly encode specific files.
 */
public class CmsEncryptedAsicWriter implements IAsicWriter
{
  static
  {
    BCHelper.getProvider ();
  }

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

  @Override
  public IAsicWriter add (final InputStream inputStream,
                          final String filename,
                          final IMimeType mimeType) throws IOException
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

  public IAsicWriter addEncrypted (final File file, final String entryName, final IMimeType mimeType) throws IOException
  {
    return addEncrypted (file.toPath (), entryName, mimeType);
  }

  public IAsicWriter addEncrypted (final Path path, final String entryName, final IMimeType mimeType) throws IOException
  {
    try (InputStream inputStream = Files.newInputStream (path))
    {
      addEncrypted (inputStream, entryName, mimeType);
    }
    return this;
  }

  public IAsicWriter addEncrypted (final InputStream inputStream,
                                   final String filename,
                                   final IMimeType mimeType) throws IOException
  {
    try
    {
      final NonBlockingByteArrayOutputStream byteArrayOutputStream = new NonBlockingByteArrayOutputStream ();
      AsicUtils.copyStream (inputStream, byteArrayOutputStream);

      final CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator ();
      cmsEnvelopedDataGenerator.addRecipientInfoGenerator (new JceKeyTransRecipientInfoGenerator (m_aCertificate).setProvider (BCHelper.getProvider ()));
      final CMSEnvelopedData data = cmsEnvelopedDataGenerator.generate (new CMSProcessableByteArray (byteArrayOutputStream.toByteArray ()),
                                                                        new JceCMSContentEncryptorBuilder (m_aCmsAlgorithm).setProvider (BCHelper.getProvider ())
                                                                                                                           .build ());

      m_aEntryNames.add (filename);

      return m_aAsicWriter.add (new NonBlockingByteArrayInputStream (data.getEncoded ()), filename + ".p7m", mimeType);
    }
    catch (final CMSException | CertificateEncodingException e)
    {
      throw new IOException (e.getMessage (), e);
    }
  }

  @Override
  public IAsicWriter setRootEntryName (final String sName)
  {
    String name = sName;
    if (m_aEntryNames.contains (name))
      name += ".p7m";

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
