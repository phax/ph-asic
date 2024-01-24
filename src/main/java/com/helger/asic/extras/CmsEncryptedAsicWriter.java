/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2024 Philip Helger (www.helger.com)
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

import javax.annotation.Nonnull;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;

import com.helger.asic.AsicUtils;
import com.helger.asic.IAsicWriter;
import com.helger.asic.SignatureHelper;
import com.helger.bc.PBCProvider;
import com.helger.commons.io.stream.NonBlockingByteArrayInputStream;
import com.helger.commons.io.stream.NonBlockingByteArrayOutputStream;
import com.helger.commons.mime.IMimeType;

/**
 * Wrapper to seamlessly encode specific files.
 */
public class CmsEncryptedAsicWriter implements IAsicWriter
{
  private final IAsicWriter m_aAsicWriter;
  private final X509Certificate m_aCertificate;
  private final ASN1ObjectIdentifier m_aCmsAlgorithm;

  private final Set <String> m_aEntryNames = new TreeSet <> ();

  public CmsEncryptedAsicWriter (final IAsicWriter aAsicWriter, final X509Certificate aCertificate)
  {
    this (aAsicWriter, aCertificate, CMSAlgorithm.AES256_GCM);
  }

  public CmsEncryptedAsicWriter (final IAsicWriter aAsicWriter,
                                 final X509Certificate aCertificate,
                                 final ASN1ObjectIdentifier aCMSAlgorithm)
  {
    m_aAsicWriter = aAsicWriter;
    m_aCertificate = aCertificate;
    m_aCmsAlgorithm = aCMSAlgorithm;
  }

  @Nonnull
  public IAsicWriter add (@Nonnull final InputStream aIS,
                          @Nonnull final String sFilename,
                          @Nonnull final IMimeType aMimeType) throws IOException
  {
    return m_aAsicWriter.add (aIS, sFilename, aMimeType);
  }

  @Nonnull
  public IAsicWriter addEncrypted (final File aFile) throws IOException
  {
    return addEncrypted (aFile.toPath ());
  }

  @Nonnull
  public IAsicWriter addEncrypted (final File aFile, final String sEntryName) throws IOException
  {
    return addEncrypted (aFile.toPath (), sEntryName);
  }

  @Nonnull
  public IAsicWriter addEncrypted (final Path aFile) throws IOException
  {
    return addEncrypted (aFile, aFile.toFile ().getName ());
  }

  @Nonnull
  public IAsicWriter addEncrypted (final Path aFile, final String sEntryName) throws IOException
  {
    try (final InputStream aIS = Files.newInputStream (aFile))
    {
      addEncrypted (aIS, sEntryName);
    }
    return this;
  }

  @Nonnull
  public IAsicWriter addEncrypted (final InputStream aIS, final String sFilename) throws IOException
  {
    return addEncrypted (aIS, sFilename, AsicUtils.detectMime (sFilename));
  }

  @Nonnull
  public IAsicWriter addEncrypted (final File aFile,
                                   final String sEntryName,
                                   final IMimeType aMimeType) throws IOException
  {
    return addEncrypted (aFile.toPath (), sEntryName, aMimeType);
  }

  @Nonnull
  public IAsicWriter addEncrypted (final Path aFile,
                                   final String sEntryName,
                                   final IMimeType aMimeType) throws IOException
  {
    try (final InputStream aIS = Files.newInputStream (aFile))
    {
      addEncrypted (aIS, sEntryName, aMimeType);
    }
    return this;
  }

  @Nonnull
  public IAsicWriter addEncrypted (final InputStream aIS,
                                   final String sFilename,
                                   final IMimeType aMimeType) throws IOException
  {
    try (final NonBlockingByteArrayOutputStream aBAOS = new NonBlockingByteArrayOutputStream ())
    {
      AsicUtils.copyStream (aIS, aBAOS);

      final CMSEnvelopedDataGenerator aCMSEnvelopedDataGenerator = new CMSEnvelopedDataGenerator ();
      aCMSEnvelopedDataGenerator.addRecipientInfoGenerator (new JceKeyTransRecipientInfoGenerator (m_aCertificate).setProvider (PBCProvider.getProvider ()));
      final CMSEnvelopedData aData = aCMSEnvelopedDataGenerator.generate (new CMSProcessableByteArray (aBAOS.toByteArray ()),
                                                                          new JceCMSContentEncryptorBuilder (m_aCmsAlgorithm).setProvider (PBCProvider.getProvider ())
                                                                                                                             .build ());

      m_aEntryNames.add (sFilename);

      return m_aAsicWriter.add (new NonBlockingByteArrayInputStream (aData.getEncoded ()),
                                sFilename + ".p7m",
                                aMimeType);
    }
    catch (final CMSException | CertificateEncodingException e)
    {
      throw new IOException (e.getMessage (), e);
    }
  }

  @Nonnull
  public IAsicWriter setRootEntryName (final String sName)
  {
    String name = sName;
    if (m_aEntryNames.contains (name))
      name += ".p7m";

    return m_aAsicWriter.setRootEntryName (name);
  }

  @Nonnull
  public IAsicWriter sign (@Nonnull final SignatureHelper aSH) throws IOException
  {
    return m_aAsicWriter.sign (aSH);
  }
}
