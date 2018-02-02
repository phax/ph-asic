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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;

import javax.annotation.Nonnull;
import javax.annotation.WillNotClose;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.io.stream.NonBlockingByteArrayOutputStream;
import com.helger.commons.io.stream.NonClosingInputStream;
import com.helger.commons.io.stream.StreamHelper;
import com.helger.commons.mime.EMimeContentType;
import com.helger.commons.mime.IMimeType;
import com.helger.commons.mime.MimeTypeParser;

public class AsicUtils
{
  private static final Logger logger = LoggerFactory.getLogger (AsicUtils.class);

  /** The MIME type, which should be the very first entry in the container */
  public static final IMimeType MIMETYPE_ASICE = EMimeContentType.APPLICATION.buildMimeType ("vnd.etsi.asic-e+zip");

  static final Pattern PATTERN_CADES_MANIFEST = Pattern.compile ("META-INF/asicmanifest(.*)\\.xml",
                                                                 Pattern.CASE_INSENSITIVE);
  static final Pattern PATTERN_CADES_SIGNATURE = Pattern.compile ("META-INF/signature(.*)\\.p7s",
                                                                  Pattern.CASE_INSENSITIVE);
  static final Pattern PATTERN_XADES_SIGNATURES = Pattern.compile ("META-INF/signatures(.*)\\.xml",
                                                                   Pattern.CASE_INSENSITIVE);

  static final Pattern PATTERN_EXTENSION_ASICE = Pattern.compile (".+\\.(asice|sce)", Pattern.CASE_INSENSITIVE);

  AsicUtils ()
  {
    // No action
  }

  /**
   * Combine multiple containers to one container. OASIS OpenDocument manifest
   * is regenerated if all source containers contains valid manifest.
   *
   * @param outputStream
   *        Stream for target container.
   * @param inputStreams
   *        Streams for source containers.
   * @throws IOException
   *         in case of error
   */
  public static void combine (@Nonnull final OutputStream outputStream,
                              @Nonnull final InputStream... inputStreams) throws IOException
  {
    // Statuses
    int manifestCounter = 0;
    int fileCounter = 0;
    boolean containsRootFile = false;

    // Open target container
    try (final AsicOutputStream target = new AsicOutputStream (outputStream))
    {
      // Prepare to combine OASIS OpenDocument Manifests
      final OasisManifest oasisManifest = new OasisManifest (MIMETYPE_ASICE);

      for (final InputStream inputStream : inputStreams)
      {
        // Open source container
        try (final AsicInputStream source = new AsicInputStream (inputStream))
        {
          // Read entries
          ZipEntry zipEntry;
          while ((zipEntry = source.getNextEntry ()) != null)
          {
            if (PATTERN_CADES_MANIFEST.matcher (zipEntry.getName ()).matches ())
            {
              // Fetch content
              final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream ();
              copyStream (source, byteArrayOutputStream);

              // Read manifest
              final ManifestVerifier manifestVerifier = new ManifestVerifier (null);
              CadesAsicManifest.extractAndVerify (byteArrayOutputStream.toString (), manifestVerifier);

              // Make sure only on rootfile makes it to the source container
              if (manifestVerifier.getAsicManifest ().getRootfile () != null)
              {
                if (containsRootFile)
                  throw new IllegalStateException ("Multiple rootfiles is not allowed when combining containers.");
                containsRootFile = true;
              }

              // Write manifest to container
              ++manifestCounter;
              target.putNextEntry (new ZipEntry ("META-INF/asicmanifest" + manifestCounter + ".xml"));
              copyStream (new ByteArrayInputStream (byteArrayOutputStream.toByteArray ()), target);
            }
            else
              if (PATTERN_XADES_SIGNATURES.matcher (zipEntry.getName ()).matches ())
              {
                // Copy content to target container
                ++manifestCounter;
                target.putNextEntry (new ZipEntry ("META-INF/signatures" + manifestCounter + ".xml"));
                copyStream (source, target);
              }
              else
                if (zipEntry.getName ().equals ("META-INF/manifest.xml"))
                {
                  // Fetch content
                  final NonBlockingByteArrayOutputStream aBAOS = new NonBlockingByteArrayOutputStream ();
                  copyStream (source, aBAOS);

                  // Copy entries
                  oasisManifest.addAll (new OasisManifest (aBAOS.getAsInputStream ()));

                  // Nothing to write to target container
                  target.closeEntry ();
                  continue;
                }
                else
                {
                  // Copy content to target container
                  target.putNextEntry (zipEntry);
                  copyStream (source, target);

                  if (!zipEntry.getName ().startsWith ("META-INF/"))
                    fileCounter++;
                }

            source.closeEntry ();
            target.closeEntry ();
          }

          // Close source container
        }
      }

      // Add manifest if it contains the same amount of files as the container.
      if (oasisManifest.getFileEntryCount () == fileCounter + 1)
        target.writeZipEntry ("META-INF/manifest.xml", oasisManifest.getAsBytes ());

      // Close target container
    }
  }

  public static IMimeType detectMime (final String filename) throws IOException
  {
    // Use Files to find content type
    String mimeType = Files.probeContentType (Paths.get (filename));

    // Use URLConnection to find content type
    if (mimeType == null)
    {
      logger.info ("Unable to determine MIME type using Files.probeContentType(), trying URLConnection.getFileNameMap()");
      mimeType = URLConnection.getFileNameMap ().getContentTypeFor (filename);
    }

    // Throw exception if content type is not detected
    if (mimeType == null)
      throw new IllegalStateException ("Unable to determine MIME type of " + filename);

    return MimeTypeParser.parseMimeType (mimeType);
  }

  public static void copyStream (@WillNotClose final InputStream aIS, @WillNotClose final OutputStream aOS)
  {
    StreamHelper.copyInputStreamToOutputStream (new NonClosingInputStream (aIS), aOS);
  }
}
