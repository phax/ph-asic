/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2026 Philip Helger (www.helger.com)
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

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.io.zip.LimitedZipInputStream;
import com.helger.io.zip.ZipWalkerSettings;

public class AsicInputStream extends LimitedZipInputStream
{
  public static final String ZIPENTRY_NAME_MIMETYPE = "mimetype";
  /**
   * The maximum size of the "mimetype" entry in bytes. Its expected content is much shorter.
   *
   * @since 4.1.1
   */
  public static final int MAX_MIMETYPE_ENTRY_BYTES = 1024;
  private static final Logger LOGGER = LoggerFactory.getLogger (AsicInputStream.class);

  /**
   * Constructor with the default limits of {@link ZipWalkerSettings}.
   *
   * @param aIS
   *        The ASiC container to read. May not be <code>null</code>.
   */
  public AsicInputStream (@NonNull final InputStream aIS)
  {
    super (aIS);
  }

  /**
   * Constructor.
   *
   * @param aIS
   *        The ASiC container to read. May not be <code>null</code>.
   * @param aZipSettings
   *        The limits for reading the container as ZIP archive (number of entries, total
   *        uncompressed size). May not be <code>null</code>.
   * @since 4.1.1
   */
  public AsicInputStream (@NonNull final InputStream aIS, @NonNull final ZipWalkerSettings aZipSettings)
  {
    super (aIS, aZipSettings);
  }

  @Override
  public ZipEntry getNextEntry () throws IOException
  {
    ZipEntry aZipEntry = super.getNextEntry ();

    if (aZipEntry != null && aZipEntry.getName ().equals (ZIPENTRY_NAME_MIMETYPE))
    {
      // Read at most one byte more than allowed, to detect a too large entry
      final byte [] aMimeType = readNBytes (MAX_MIMETYPE_ENTRY_BYTES + 1);
      if (aMimeType.length > MAX_MIMETYPE_ENTRY_BYTES)
        throw new IllegalStateException ("The mimetype entry of the ASiC container exceeds " +
                                         MAX_MIMETYPE_ENTRY_BYTES +
                                         " bytes");

      final String sMimeType = new String (aMimeType, StandardCharsets.ISO_8859_1);
      if (LOGGER.isDebugEnabled ())
        LOGGER.debug ("Content of mimetype: " + sMimeType);
      if (!AsicUtils.MIMETYPE_ASICE.getAsString ().equals (sMimeType))
        throw new IllegalStateException ("Content is not ASiC-E container.");

      // Fetch next
      aZipEntry = super.getNextEntry ();
    }

    return aZipEntry;
  }
}
