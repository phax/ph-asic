/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2025 Philip Helger (www.helger.com)
 * philip[at]helger[dot]com
 *
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/
 */
package com.helger.asic;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.jspecify.annotations.NonNull;

import com.helger.annotation.WillNotClose;
import com.helger.mime.IMimeType;

public interface IAsicWriter
{
  /**
   * Adds another data object to the ASiC archive.
   *
   * @param aFile
   *        references the file to be added as a data object. The name of the
   *        entry is extracted from the File object.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of IO error
   */
  @NonNull
  default IAsicWriter add (@NonNull final File aFile) throws IOException
  {
    return add (aFile.toPath ());
  }

  /**
   * Adds another data object to the ASiC container, using the supplied name as
   * the zip entry name
   *
   * @param aFile
   *        references the file to be added as a data object.
   * @param sFilename
   *        the archive entry name to be used.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of error
   */
  @NonNull
  default IAsicWriter add (@NonNull final File aFile, @NonNull final String sFilename) throws IOException
  {
    return add (aFile.toPath (), sFilename);
  }

  /**
   * Adds another data object to the ASiC archive
   *
   * @param aFile
   *        references the file to be added.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of an IO error
   * @see #add(File)
   */
  @NonNull
  default IAsicWriter add (@NonNull final Path aFile) throws IOException
  {
    return add (aFile, aFile.toFile ().getName ());
  }

  /**
   * Adds another data object to the ASiC container under the entry name
   * provided.
   *
   * @param aFile
   *        reference to this AsicWriter.
   * @param sFilename
   *        the archive entry name to be used.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of an IO error
   * @see #add(File, String)
   */
  @NonNull
  default IAsicWriter add (@NonNull final Path aFile, @NonNull final String sFilename) throws IOException
  {
    try (final InputStream inputStream = Files.newInputStream (aFile))
    {
      add (inputStream, sFilename);
    }
    return this;
  }

  /**
   * Adds the data provided by the stream into the ASiC archive, using the name
   * of the supplied file as the entry name.
   *
   * @param aIS
   *        input stream of data.
   * @param sFilename
   *        the name of a file, which must be available in the file system in
   *        order to determine the MIME type.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of an IO error
   */
  @NonNull
  default IAsicWriter add (@NonNull @WillNotClose final InputStream aIS,
                           @NonNull final String sFilename) throws IOException
  {
    // Add file to container
    return add (aIS, sFilename, AsicUtils.detectMime (sFilename));
  }

  /**
   * Adds the contents of a file into the ASiC archive using the supplied entry
   * name and MIME type.
   *
   * @param aFile
   *        references the file to be added as a data object.
   * @param sFilename
   *        the archive entry name to be used.
   * @param aMimeType
   *        explicitly identifies the MIME type of the entry.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of an IO error
   */
  @NonNull
  default IAsicWriter add (@NonNull final File aFile,
                           @NonNull final String sFilename,
                           @NonNull final IMimeType aMimeType) throws IOException
  {
    return add (aFile.toPath (), sFilename, aMimeType);
  }

  /**
   * Adds the contents of a file into the ASiC archive using the supplied entry
   * name and MIME type.
   *
   * @param aFile
   *        references the file to be added as a data object.
   * @param sFilename
   *        the archive entry name to be used.
   * @param aMimeType
   *        explicitly identifies the MIME type of the entry.
   * @return reference to this AsicWriter
   * @throws IOException
   *         on IO error
   */
  @NonNull
  default IAsicWriter add (@NonNull final Path aFile,
                           @NonNull final String sFilename,
                           @NonNull final IMimeType aMimeType) throws IOException
  {
    try (final InputStream aIS = Files.newInputStream (aFile))
    {
      add (aIS, sFilename, aMimeType);
    }
    return this;
  }

  /**
   * Adds the contents of an input stream into the ASiC archive, under a given
   * entry name and explicitly identifying the MIME type.
   *
   * @param aIS
   *        Input stream to add
   * @param sFilename
   *        the archive entry name to be used.
   * @param aMimeType
   *        explicitly identifies the MIME type of the entry.
   * @return reference to this AsicWriter
   * @throws IOException
   *         on IO error
   */
  @NonNull
  IAsicWriter add (@NonNull InputStream aIS,
                   @NonNull String sFilename,
                   @NonNull IMimeType aMimeType) throws IOException;

  /**
   * Specifies which entry (file) represents the "root" document, i.e. which
   * business document to read first.
   *
   * @param name
   *        of entry holding the root document.
   * @return reference to this AsicWriter
   */
  @NonNull
  IAsicWriter setRootEntryName (String name);

  /**
   * Allows re-use of the same SignatureHelper object when creating multiple
   * ASiC archive and hence the need to create multiple signatures.
   *
   * @param aSH
   *        instantiated SignatureHelper
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of an IO error
   */
  @NonNull
  IAsicWriter sign (@NonNull SignatureHelper aSH) throws IOException;
}
