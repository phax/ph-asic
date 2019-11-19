/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2019 Philip Helger (www.helger.com)
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
import com.helger.asic.IAsicReader;
import com.helger.asic.jaxb.asic.AsicManifest;
import com.helger.bc.PBCProvider;
import com.helger.commons.io.stream.NonBlockingByteArrayInputStream;
import com.helger.commons.io.stream.NonBlockingByteArrayOutputStream;

/**
 * Wrapper to seamlessly decode encoded files.
 */
public class CmsEncryptedAsicReader implements IAsicReader
{
  private final IAsicReader m_aAsicReader;
  private final PrivateKey m_aPrivateKey;
  private String m_sCurrentFile;

  public CmsEncryptedAsicReader (@Nonnull final IAsicReader aAsicReader, final PrivateKey aPrivateKey)
  {
    m_aAsicReader = aAsicReader;
    m_aPrivateKey = aPrivateKey;
  }

  public String getNextFile () throws IOException
  {
    m_sCurrentFile = m_aAsicReader.getNextFile ();
    if (m_sCurrentFile == null)
      return null;

    return m_sCurrentFile.endsWith (".p7m") ? m_sCurrentFile.substring (0, m_sCurrentFile.length () - 4)
                                            : m_sCurrentFile;
  }

  public void writeFile (final File aFile) throws IOException
  {
    writeFile (aFile.toPath ());
  }

  public void writeFile (final Path aFile) throws IOException
  {
    try (OutputStream outputStream = Files.newOutputStream (aFile))
    {
      writeFile (outputStream);
    }
  }

  public void writeFile (final OutputStream aOS) throws IOException
  {
    if (m_sCurrentFile.endsWith (".p7m"))
    {
      try (final NonBlockingByteArrayOutputStream aBAOS = new NonBlockingByteArrayOutputStream ())
      {
        m_aAsicReader.writeFile (aBAOS);

        final CMSEnvelopedDataParser aCMSEnvelopedDataParser = new CMSEnvelopedDataParser (aBAOS.getAsInputStream ());
        // expect exactly one recipient
        final Collection <RecipientInformation> aRecipients = aCMSEnvelopedDataParser.getRecipientInfos ()
                                                                                     .getRecipients ();
        if (aRecipients.size () != 1)
          throw new IllegalArgumentException ("Found not exactly one recipient but " + aRecipients.size ());

        // retrieve recipient and decode it
        final RecipientInformation aRecipientInfo = aRecipients.iterator ().next ();
        final byte [] aDecryptedData = aRecipientInfo.getContent (new JceKeyTransEnvelopedRecipient (m_aPrivateKey).setProvider (PBCProvider.getProvider ()));

        AsicUtils.copyStream (new NonBlockingByteArrayInputStream (aDecryptedData), aOS);
      }
      catch (final CMSException e)
      {
        throw new IOException (e.getMessage (), e);
      }
    }
    else
    {
      m_aAsicReader.writeFile (aOS);
    }
  }

  @Nonnull
  public InputStream inputStream () throws IOException
  {
    final PipedInputStream aPIS = new PipedInputStream ();
    final PipedOutputStream aPOS = new PipedOutputStream (aPIS);

    writeFile (aPOS);
    return aPIS;
  }

  public void close () throws IOException
  {
    m_aAsicReader.close ();
  }

  @Nonnull
  public AsicManifest getAsicManifest ()
  {
    final AsicManifest ret = m_aAsicReader.getAsicManifest ();

    final String sRootfile = ret.getRootfile ();
    if (sRootfile != null && sRootfile.endsWith (".p7m"))
      ret.setRootfile (sRootfile.substring (0, sRootfile.length () - 4));

    return ret;
  }
}
