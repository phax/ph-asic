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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;

import javax.annotation.Nonnull;
import javax.annotation.WillNotClose;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.annotation.PresentForCodeCoverage;
import com.helger.commons.io.stream.NonBlockingByteArrayOutputStream;
import com.helger.commons.io.stream.NonClosingInputStream;
import com.helger.commons.io.stream.StreamHelper;
import com.helger.commons.mime.EMimeContentType;
import com.helger.commons.mime.IMimeType;
import com.helger.commons.mime.MimeTypeParser;

public final class AsicUtils
{
  private static final Logger LOG = LoggerFactory.getLogger (AsicUtils.class);

  /** The MIME type, which should be the very first entry in the container */
  public static final IMimeType MIMETYPE_ASICE = EMimeContentType.APPLICATION.buildMimeType ("vnd.etsi.asic-e+zip");

  public static final Pattern PATTERN_CADES_MANIFEST = Pattern.compile ("META-INF/asicmanifest(.*)\\.xml",
                                                                        Pattern.CASE_INSENSITIVE);
  public static final Pattern PATTERN_CADES_SIGNATURE = Pattern.compile ("META-INF/signature(.*)\\.p7s",
                                                                         Pattern.CASE_INSENSITIVE);
  public static final Pattern PATTERN_XADES_SIGNATURES = Pattern.compile ("META-INF/signatures(.*)\\.xml",
                                                                          Pattern.CASE_INSENSITIVE);

  public static final Pattern PATTERN_EXTENSION_ASICE = Pattern.compile (".+\\.(asice|sce)", Pattern.CASE_INSENSITIVE);

  @PresentForCodeCoverage
  private static final AsicUtils s_aInstance = new AsicUtils ();

  private AsicUtils ()
  {}

  /**
   * Combine multiple containers to one container. OASIS OpenDocument manifest
   * is regenerated if all source containers contains valid manifest.
   *
   * @param aOS
   *        Stream for target container.
   * @param inputStreams
   *        Streams for source containers.
   * @throws IOException
   *         in case of error
   */
  public static void combine (@Nonnull final OutputStream aOS,
                              @Nonnull final InputStream... inputStreams) throws IOException
  {
    // Statuses
    int nManifestCounter = 0;
    int nFileCounter = 0;
    boolean bContainsRootFile = false;

    // Open target container
    try (final AsicOutputStream target = new AsicOutputStream (aOS))
    {
      // Prepare to combine OASIS OpenDocument Manifests
      final OasisManifest aOasisManifest = new OasisManifest (MIMETYPE_ASICE);

      for (final InputStream aIS : inputStreams)
      {
        // Open source container
        try (final AsicInputStream source = new AsicInputStream (aIS))
        {
          // Read entries
          ZipEntry zipEntry;
          while ((zipEntry = source.getNextEntry ()) != null)
          {
            if (PATTERN_CADES_MANIFEST.matcher (zipEntry.getName ()).matches ())
            {
              // Fetch content
              final NonBlockingByteArrayOutputStream byteArrayOutputStream = new NonBlockingByteArrayOutputStream ();
              copyStream (source, byteArrayOutputStream);

              // Read manifest
              final ManifestVerifier manifestVerifier = new ManifestVerifier (null);
              CadesAsicManifest.extractAndVerify (byteArrayOutputStream.getAsString (StandardCharsets.UTF_8),
                                                  manifestVerifier);

              // Make sure only on rootfile makes it to the source container
              if (manifestVerifier.getAsicManifest ().getRootfile () != null)
              {
                if (bContainsRootFile)
                  throw new IllegalStateException ("Multiple rootfiles is not allowed when combining containers.");
                bContainsRootFile = true;
              }

              // Write manifest to container
              ++nManifestCounter;
              target.putNextEntry (new ZipEntry ("META-INF/asicmanifest" + nManifestCounter + ".xml"));
              copyStream (byteArrayOutputStream.getAsInputStream (), target);
            }
            else
              if (PATTERN_XADES_SIGNATURES.matcher (zipEntry.getName ()).matches ())
              {
                // Copy content to target container
                ++nManifestCounter;
                target.putNextEntry (new ZipEntry ("META-INF/signatures" + nManifestCounter + ".xml"));
                copyStream (source, target);
              }
              else
                if (zipEntry.getName ().equals ("META-INF/manifest.xml"))
                {
                  // Fetch content
                  final NonBlockingByteArrayOutputStream aBAOS = new NonBlockingByteArrayOutputStream ();
                  copyStream (source, aBAOS);

                  // Copy entries
                  aOasisManifest.addAll (new OasisManifest (aBAOS.getAsInputStream ()));

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
                    nFileCounter++;
                }

            source.closeEntry ();
            target.closeEntry ();
          }

          // Close source container
        }
      }

      // Add manifest if it contains the same amount of files as the container.
      if (aOasisManifest.getFileEntryCount () == nFileCounter + 1)
        target.writeZipEntry ("META-INF/manifest.xml", aOasisManifest.getAsBytes ());

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
      LOG.info ("Unable to determine MIME type of '" +
                filename +
                "' using Files.probeContentType(), trying URLConnection.getFileNameMap()");
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
