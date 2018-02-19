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
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.annotation.Nonempty;
import com.helger.commons.mime.IMimeType;

/**
 * Stream handling requirements to ASiC files.
 */
public class AsicOutputStream extends ZipOutputStream
{
  private static final Logger LOG = LoggerFactory.getLogger (AsicOutputStream.class);

  public AsicOutputStream (@Nonnull final OutputStream aOS) throws IOException
  {
    super (aOS);

    setComment ("mimetype=" + AsicUtils.MIMETYPE_ASICE.getAsString ());
    _putMimeTypeAsFirstEntry (AsicUtils.MIMETYPE_ASICE);
  }

  private void _putMimeTypeAsFirstEntry (@Nonnull @Nonempty final IMimeType aMimeType) throws IOException
  {
    final String sMimeType = aMimeType.getAsString ();
    final ZipEntry mimetypeEntry = new ZipEntry ("mimetype");
    mimetypeEntry.setComment ("mimetype=" + sMimeType);
    mimetypeEntry.setMethod (ZipEntry.STORED);

    final byte [] aContentBytes = sMimeType.getBytes (StandardCharsets.ISO_8859_1);
    mimetypeEntry.setSize (aContentBytes.length);

    final CRC32 crc32 = new CRC32 ();
    crc32.update (aContentBytes);
    mimetypeEntry.setCrc (crc32.getValue ());

    writeZipEntry (mimetypeEntry, aContentBytes);
  }

  protected void writeZipEntry (final String filename, final byte [] bytes) throws IOException
  {
    writeZipEntry (new ZipEntry (filename), bytes);
  }

  protected void writeZipEntry (final ZipEntry zipEntry, final byte [] bytes) throws IOException
  {
    try
    {
      if (LOG.isDebugEnabled ())
        LOG.debug ("Writing entry '" + zipEntry.getName () + "' to container");
      putNextEntry (zipEntry);
      write (bytes);
      closeEntry ();
    }
    catch (final IOException e)
    {
      throw new IOException ("Unable to create new ZIP entry for " + zipEntry.getName (), e);
    }
  }
}
