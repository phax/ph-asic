/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2021 Philip Helger (www.helger.com)
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
import javax.annotation.Nullable;
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
import com.helger.commons.mime.MimeTypeParserException;

public final class AsicUtils
{
  private static final Logger LOGGER = LoggerFactory.getLogger (AsicUtils.class);

  /** The MIME type, which should be the very first entry in the container */
  public static final IMimeType MIMETYPE_ASICE = EMimeContentType.APPLICATION.buildMimeType ("vnd.etsi.asic-e+zip");

  public static final String ASIC_MANIFEST_BASENAME = "ASiCManifest";
  public static final Pattern PATTERN_CADES_MANIFEST = Pattern.compile ("META-INF/" +
                                                                        ASIC_MANIFEST_BASENAME +
                                                                        "(.*)\\.xml",
                                                                        Pattern.CASE_INSENSITIVE);
  public static final String SIGNATURE_BASENAME = "signature";
  public static final Pattern PATTERN_CADES_SIGNATURE = Pattern.compile ("META-INF/" +
                                                                         SIGNATURE_BASENAME +
                                                                         "(.*)\\.p7s",
                                                                         Pattern.CASE_INSENSITIVE);
  public static final String SIGNATURES_BASENAME = "signatures";
  public static final Pattern PATTERN_XADES_SIGNATURES = Pattern.compile ("META-INF/" +
                                                                          SIGNATURES_BASENAME +
                                                                          "(.*)\\.xml",
                                                                          Pattern.CASE_INSENSITIVE);
  public static final String OASIS_MANIFEST_BASENAME = "manifest";
  public static final Pattern PATTERN_OASIS_MANIFEST = Pattern.compile ("META-INF/" +
                                                                        OASIS_MANIFEST_BASENAME +
                                                                        "\\.xml",
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
   * @param aISs
   *        Streams for source containers.
   * @throws IOException
   *         in case of error
   */
  public static void combine (@Nonnull final OutputStream aOS, @Nonnull final InputStream... aISs) throws IOException
  {
    // Statuses
    int nManifestCounter = 0;
    int nFileCounter = 0;
    boolean bContainsRootFile = false;

    // Open target container
    try (final AsicOutputStream aAOS = new AsicOutputStream (aOS))
    {
      // Prepare to combine OASIS OpenDocument Manifests
      final OasisManifest aOasisManifest = new OasisManifest (MIMETYPE_ASICE);

      for (final InputStream aIS : aISs)
      {
        // Open source container
        try (final AsicInputStream aAIS = new AsicInputStream (aIS))
        {
          // Read entries
          ZipEntry aZipEntry;
          while ((aZipEntry = aAIS.getNextEntry ()) != null)
          {
            if (PATTERN_CADES_MANIFEST.matcher (aZipEntry.getName ()).matches ())
            {
              // Fetch content
              try (final NonBlockingByteArrayOutputStream aBAOS = new NonBlockingByteArrayOutputStream ())
              {
                copyStream (aAIS, aBAOS);

                // Read manifest
                final ManifestVerifier aManifestVerifier = new ManifestVerifier (null);
                CadesAsicManifest.extractAndVerify (aBAOS.getAsString (StandardCharsets.UTF_8), aManifestVerifier);

                // Make sure only on rootfile makes it to the source container
                if (aManifestVerifier.getAsicManifest ().getRootfile () != null)
                {
                  if (bContainsRootFile)
                    throw new IllegalStateException ("Multiple rootfiles is not allowed when combining containers.");
                  bContainsRootFile = true;
                }

                // Write manifest to container
                ++nManifestCounter;
                aAOS.putNextEntry (new ZipEntry ("META-INF/" +
                                                 AsicUtils.ASIC_MANIFEST_BASENAME +
                                                 nManifestCounter +
                                                 ".xml"));
                copyStream (aBAOS.getAsInputStream (), aAOS);
              }
            }
            else
              if (PATTERN_XADES_SIGNATURES.matcher (aZipEntry.getName ()).matches ())
              {
                // Copy content to target container
                ++nManifestCounter;
                aAOS.putNextEntry (new ZipEntry ("META-INF/" + SIGNATURES_BASENAME + nManifestCounter + ".xml"));
                copyStream (aAIS, aAOS);
              }
              else
                if (PATTERN_OASIS_MANIFEST.matcher (aZipEntry.getName ()).matches ())
                {
                  // Fetch content
                  final NonBlockingByteArrayOutputStream aBAOS = new NonBlockingByteArrayOutputStream ();
                  copyStream (aAIS, aBAOS);

                  // Copy entries
                  aOasisManifest.addAll (new OasisManifest (aBAOS.getAsInputStream ()));

                  // Nothing to write to target container
                  aAOS.closeEntry ();
                  continue;
                }
                else
                {
                  // Copy content to target container
                  aAOS.putNextEntry (aZipEntry);
                  copyStream (aAIS, aAOS);

                  if (!aZipEntry.getName ().startsWith ("META-INF/"))
                    nFileCounter++;
                }

            aAIS.closeEntry ();
            aAOS.closeEntry ();
          }

          // Close source container
        }
      }

      // Add manifest if it contains the same amount of files as the container.
      if (aOasisManifest.getFileEntryCount () == nFileCounter + 1)
        aAOS.writeZipEntry ("META-INF/" + OASIS_MANIFEST_BASENAME + ".xml", aOasisManifest.getAsBytes ());

      // Close target container
    }
  }

  @Nullable
  public static IMimeType detectMime (final String sFilename) throws IOException
  {
    // Use Files to find content type
    String sMimeType = Files.probeContentType (Paths.get (sFilename));

    // Use URLConnection to find content type
    if (sMimeType == null)
    {
      LOGGER.info ("Unable to determine MIME type of '" +
                   sFilename +
                   "' using Files.probeContentType(), trying URLConnection.getFileNameMap()");
      sMimeType = URLConnection.getFileNameMap ().getContentTypeFor (sFilename);
    }

    // Throw exception if content type is not detected
    if (sMimeType == null)
      throw new IllegalStateException ("Unable to determine MIME type of " + sFilename);

    try
    {
      return MimeTypeParser.parseMimeType (sMimeType);
    }
    catch (final MimeTypeParserException ex)
    {
      throw new IOException ("Failed to parse MIME Type", ex);
    }
  }

  public static void copyStream (@WillNotClose final InputStream aIS, @WillNotClose final OutputStream aOS)
  {
    StreamHelper.copyInputStreamToOutputStream (new NonClosingInputStream (aIS), aOS);
  }
}
