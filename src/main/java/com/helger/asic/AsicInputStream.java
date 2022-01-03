/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2022 Philip Helger (www.helger.com)
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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.io.stream.NonBlockingByteArrayOutputStream;

public class AsicInputStream extends ZipInputStream
{
  public static final String ZIPENTRY_NAME_MIMETYPE = "mimetype";
  private static final Logger LOGGER = LoggerFactory.getLogger (AsicInputStream.class);

  public AsicInputStream (@Nonnull final InputStream aIS)
  {
    super (aIS);
  }

  @Override
  public ZipEntry getNextEntry () throws IOException
  {
    ZipEntry aZipEntry = super.getNextEntry ();

    if (aZipEntry != null && aZipEntry.getName ().equals (ZIPENTRY_NAME_MIMETYPE))
    {
      try (final NonBlockingByteArrayOutputStream aBAOS = new NonBlockingByteArrayOutputStream ();)
      {
        AsicUtils.copyStream (this, aBAOS);
        final String sMimeType = aBAOS.getAsString (StandardCharsets.ISO_8859_1);

        if (LOGGER.isDebugEnabled ())
          LOGGER.debug ("Content of mimetype: " + sMimeType);
        if (!AsicUtils.MIMETYPE_ASICE.getAsString ().equals (sMimeType))
          throw new IllegalStateException ("Content is not ASiC-E container.");
      }

      // Fetch next
      aZipEntry = super.getNextEntry ();
    }

    return aZipEntry;
  }
}
