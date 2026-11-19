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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.jspecify.annotations.NonNull;
import org.junit.Test;

import com.helger.base.io.nonblocking.NonBlockingByteArrayInputStream;
import com.helger.base.io.nonblocking.NonBlockingByteArrayOutputStream;
import com.helger.base.io.stream.StringInputStream;
import com.helger.io.zip.EZipWalkResult;
import com.helger.io.zip.InvalidZipException;
import com.helger.io.zip.ZipWalkerSettings;
import com.helger.mime.CMimeType;

/**
 * Test the ZIP limits of the ASiC readers.
 *
 * @author Philip Helger
 */
public final class AsicReaderLimitsTest
{
  private static final SignatureHelper SIGNATURE_HELPER = TestUtil.createSignatureHelper ();

  private static byte @NonNull [] _zip (final Object @NonNull... aNamesAndContents) throws IOException
  {
    final NonBlockingByteArrayOutputStream aBAOS = new NonBlockingByteArrayOutputStream ();
    try (final ZipOutputStream aZOS = new ZipOutputStream (aBAOS))
    {
      for (int i = 0; i < aNamesAndContents.length; i += 2)
      {
        aZOS.putNextEntry (new ZipEntry ((String) aNamesAndContents[i]));
        final Object aContent = aNamesAndContents[i + 1];
        if (aContent instanceof final String sContent)
          aZOS.write (sContent.getBytes (StandardCharsets.ISO_8859_1));
        else
          aZOS.write ((byte []) aContent);
        aZOS.closeEntry ();
      }
    }
    return aBAOS.toByteArray ();
  }

  private static void _readAll (final byte @NonNull [] aContainer,
                                @NonNull final AsicReaderFactory aFactory) throws IOException
  {
    try (final IAsicReader aReader = aFactory.open (new NonBlockingByteArrayInputStream (aContainer)))
    {
      while (aReader.getNextFile () != null)
        aReader.writeFile (new NonBlockingByteArrayOutputStream ());
    }
  }

  @NonNull
  private static byte [] _createSignedContainer () throws IOException
  {
    final NonBlockingByteArrayOutputStream aBAOS = new NonBlockingByteArrayOutputStream ();
    AsicWriterFactory.newFactory (ESignatureMethod.CAdES)
                     .newContainer (aBAOS)
                     .add (new StringInputStream ("0123456789".repeat (100), StandardCharsets.ISO_8859_1),
                           "content.txt",
                           CMimeType.TEXT_PLAIN)
                     .sign (SIGNATURE_HELPER);
    return aBAOS.toByteArray ();
  }

  @Test
  public void testNotAZip ()
  {
    try
    {
      _readAll ("not a zip".getBytes (StandardCharsets.ISO_8859_1), AsicReaderFactory.newFactory ());
      fail ();
    }
    catch (final IOException ex)
    {
      assertTrue (ex instanceof InvalidZipException);
      assertEquals (EZipWalkResult.NOT_A_ZIP, ((InvalidZipException) ex).getReason ());
    }
  }

  @Test
  public void testMimetypeTooLarge () throws IOException
  {
    final byte [] aContainer = _zip (AsicInputStream.ZIPENTRY_NAME_MIMETYPE,
                                     new byte [AsicInputStream.MAX_MIMETYPE_ENTRY_BYTES + 1]);
    try
    {
      _readAll (aContainer, AsicReaderFactory.newFactory ());
      fail ();
    }
    catch (final IllegalStateException ex)
    {
      assertTrue (ex.getMessage (), ex.getMessage ().contains ("mimetype"));
    }
  }

  @Test
  public void testMetadataTooLarge () throws IOException
  {
    // Highly compressible, so the container itself is small
    final byte [] aContainer = _zip (AsicInputStream.ZIPENTRY_NAME_MIMETYPE,
                                     AsicUtils.MIMETYPE_ASICE.getAsString (),
                                     "META-INF/signature.p7s",
                                     new byte [AbstractAsicReader.MAX_METADATA_ENTRY_BYTES + 1]);
    try
    {
      _readAll (aContainer, AsicReaderFactory.newFactory ());
      fail ();
    }
    catch (final IllegalStateException ex)
    {
      assertTrue (ex.getMessage (), ex.getMessage ().contains ("META-INF/signature.p7s"));
    }
  }

  @Test
  public void testZipSettings () throws IOException
  {
    final byte [] aContainer = _createSignedContainer ();

    // Default limits
    _readAll (aContainer, AsicReaderFactory.newFactory ());
    AsicVerifierFactory.newFactory ().verify (new NonBlockingByteArrayInputStream (aContainer));

    // Too small for the content
    final ZipWalkerSettings aSmall = new ZipWalkerSettings ().setMaxTotalUncompressedBytes (100);
    try
    {
      _readAll (aContainer, AsicReaderFactory.newFactory ().setZipSettings (aSmall));
      fail ();
    }
    catch (final InvalidZipException ex)
    {
      assertEquals (EZipWalkResult.MAX_TOTAL_UNCOMPRESSED_BYTES_EXCEEDED, ex.getReason ());
    }
    try
    {
      AsicVerifierFactory.newFactory ()
                         .setZipSettings (aSmall)
                         .verify (new NonBlockingByteArrayInputStream (aContainer));
      fail ();
    }
    catch (final InvalidZipException ex)
    {
      assertEquals (EZipWalkResult.MAX_TOTAL_UNCOMPRESSED_BYTES_EXCEEDED, ex.getReason ());
    }

    // Too few entries
    try
    {
      _readAll (aContainer, AsicReaderFactory.newFactory ().setZipSettings (new ZipWalkerSettings ().setMaxEntryCount (1)));
      fail ();
    }
    catch (final InvalidZipException ex)
    {
      assertEquals (EZipWalkResult.MAX_ENTRY_COUNT_EXCEEDED, ex.getReason ());
    }
  }
}
