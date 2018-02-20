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
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.Collection;

import javax.annotation.Nonnull;

import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;

import com.helger.asic.AsicUtils;
import com.helger.asic.BCHelper;
import com.helger.asic.IAsicReader;
import com.helger.asic.jaxb.asic.AsicManifest;
import com.helger.commons.io.stream.NonBlockingByteArrayInputStream;
import com.helger.commons.io.stream.NonBlockingByteArrayOutputStream;

/**
 * Wrapper to seamlessly decode encoded files.
 */
public class CmsEncryptedAsicReader implements IAsicReader
{
  static
  {
    BCHelper.getProvider ();
  }

  private final IAsicReader m_aAsicReader;
  private final PrivateKey m_aPrivateKey;
  private String m_sCurrentFile;

  public CmsEncryptedAsicReader (@Nonnull final IAsicReader aAsicReader, final PrivateKey aPrivateKey)
  {
    m_aAsicReader = aAsicReader;
    m_aPrivateKey = aPrivateKey;
  }

  @Override
  public String getNextFile () throws IOException
  {
    m_sCurrentFile = m_aAsicReader.getNextFile ();
    if (m_sCurrentFile == null)
      return null;

    return m_sCurrentFile.endsWith (".p7m") ? m_sCurrentFile.substring (0, m_sCurrentFile.length () - 4)
                                            : m_sCurrentFile;
  }

  @Override
  public void writeFile (final File file) throws IOException
  {
    writeFile (file.toPath ());
  }

  @Override
  public void writeFile (final Path path) throws IOException
  {
    try (OutputStream outputStream = Files.newOutputStream (path))
    {
      writeFile (outputStream);
    }
  }

  @Override
  public void writeFile (final OutputStream outputStream) throws IOException
  {
    if (m_sCurrentFile.endsWith (".p7m"))
    {
      try
      {
        final NonBlockingByteArrayOutputStream byteArrayOutputStream = new NonBlockingByteArrayOutputStream ();
        m_aAsicReader.writeFile (byteArrayOutputStream);

        final CMSEnvelopedDataParser cmsEnvelopedDataParser = new CMSEnvelopedDataParser (byteArrayOutputStream.getAsInputStream ());
        // expect exactly one recipient
        final Collection <RecipientInformation> recipients = cmsEnvelopedDataParser.getRecipientInfos ()
                                                                                   .getRecipients ();
        if (recipients.size () != 1)
          throw new IllegalArgumentException ("Found not exactly one recipient but " + recipients.size ());

        // retrieve recipient and decode it
        final RecipientInformation aRecipientInfo = recipients.iterator ().next ();
        final byte [] aDecryptedData = aRecipientInfo.getContent (new JceKeyTransEnvelopedRecipient (m_aPrivateKey).setProvider (BCHelper.getProvider ()));

        AsicUtils.copyStream (new NonBlockingByteArrayInputStream (aDecryptedData), outputStream);
      }
      catch (final CMSException e)
      {
        throw new IOException (e.getMessage (), e);
      }
    }
    else
    {
      m_aAsicReader.writeFile (outputStream);
    }
  }

  @Override
  public InputStream inputStream () throws IOException
  {
    final PipedInputStream pipedInputStream = new PipedInputStream ();
    final PipedOutputStream pipedOutputStream = new PipedOutputStream (pipedInputStream);

    writeFile (pipedOutputStream);
    return pipedInputStream;
  }

  @Override
  public void close () throws IOException
  {
    m_aAsicReader.close ();
  }

  @Override
  public AsicManifest getAsicManifest ()
  {
    final AsicManifest asicManifest = m_aAsicReader.getAsicManifest ();

    final String rootfile = asicManifest.getRootfile ();
    if (rootfile != null && rootfile.endsWith (".p7m"))
      asicManifest.setRootfile (rootfile.substring (0, rootfile.length () - 4));

    return asicManifest;
  }
}
