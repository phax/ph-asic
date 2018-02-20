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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.WillNotClose;

import com.helger.commons.mime.IMimeType;

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
  @Nonnull
  default IAsicWriter add (@Nonnull final File aFile) throws IOException
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
  @Nonnull
  default IAsicWriter add (@Nonnull final File aFile, @Nonnull final String sFilename) throws IOException
  {
    return add (aFile.toPath (), sFilename);
  }

  /**
   * Adds another data object to the ASiC archive
   *
   * @param aPath
   *        references the file to be added.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of an IO error
   * @see #add(File)
   */
  @Nonnull
  default IAsicWriter add (@Nonnull final Path aPath) throws IOException
  {
    return add (aPath, aPath.toFile ().getName ());
  }

  /**
   * Adds another data object to the ASiC container under the entry name
   * provided.
   *
   * @param aPath
   *        reference to this AsicWriter.
   * @param sFilename
   *        the archive entry name to be used.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of an IO error
   * @see #add(File, String)
   */
  @Nonnull
  default IAsicWriter add (@Nonnull final Path aPath, @Nonnull final String sFilename) throws IOException
  {
    try (final InputStream inputStream = Files.newInputStream (aPath))
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
  @Nonnull
  default IAsicWriter add (@Nonnull @WillNotClose final InputStream aIS,
                           @Nonnull final String sFilename) throws IOException
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
  @Nonnull
  default IAsicWriter add (@Nonnull final File aFile,
                           @Nonnull final String sFilename,
                           @Nonnull final IMimeType aMimeType) throws IOException
  {
    return add (aFile.toPath (), sFilename, aMimeType);
  }

  /**
   * Adds the contents of a file into the ASiC archive using the supplied entry
   * name and MIME type.
   *
   * @param path
   *        references the file to be added as a data object.
   * @param sFilename
   *        the archive entry name to be used.
   * @param aMimeType
   *        explicitly identifies the MIME type of the entry.
   * @return reference to this AsicWriter
   * @throws IOException
   *         on IO error
   */
  @Nonnull
  default IAsicWriter add (@Nonnull final Path path,
                           @Nonnull final String sFilename,
                           @Nonnull final IMimeType aMimeType) throws IOException
  {
    try (final InputStream aIS = Files.newInputStream (path))
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
  @Nonnull
  IAsicWriter add (@Nonnull InputStream aIS,
                   @Nonnull String sFilename,
                   @Nonnull IMimeType aMimeType) throws IOException;

  /**
   * Specifies which entry (file) represents the "root" document, i.e. which
   * business document to read first.
   *
   * @param name
   *        of entry holding the root document.
   * @return reference to this AsicWriter
   */
  IAsicWriter setRootEntryName (String name);

  /**
   * Signs and closes the ASiC archive. The private and public key is obtained
   * from the supplied key store.
   *
   * @param keyStoreFile
   *        the file holding the JKS keystore file.
   * @param keyStorePassword
   *        password for the keystore
   * @param keyPassword
   *        password protecting the private key.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of an IO error
   */
  @Nonnull
  default IAsicWriter sign (final File keyStoreFile,
                            final String keyStorePassword,
                            final String keyPassword) throws IOException
  {
    return sign (keyStoreFile, keyStorePassword, null, keyPassword);
  }

  /**
   * Signs and closes the ASiC archive using the private and public key stored
   * in the supplied key store under the supplied alias name.
   *
   * @param keyStoreFile
   *        the file holding the JKS keystore file.
   * @param keyStorePassword
   *        password for the keystore
   * @param keyAlias
   *        the alias of the keystore entry holding the private and the public
   *        key.
   * @param keyPassword
   *        password protecting the private key.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of an IO error
   */
  @Nonnull
  default IAsicWriter sign (@Nonnull final File keyStoreFile,
                            @Nonnull final String keyStorePassword,
                            @Nullable final String keyAlias,
                            @Nonnull final String keyPassword) throws IOException
  {
    return sign (new SignatureHelper (keyStoreFile, keyStorePassword, keyAlias, keyPassword));
  }

  /**
   * Allows re-use of the same SignatureHelper object when creating multiple
   * ASiC archive and hence the need to create multiple signatures.
   *
   * @param signatureHelper
   *        instantiated SignatureHelper
   * @return reference to this AsicWriter
   * @see #sign(File, String, String, String)
   * @throws IOException
   *         in case of an IO error
   */
  @Nonnull
  IAsicWriter sign (@Nonnull SignatureHelper signatureHelper) throws IOException;
}
