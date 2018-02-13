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
   * @param file
   *        references the file to be added as a data object. The name of the
   *        entry is extracted from the File object.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of IO error
   */
  @Nonnull
  default IAsicWriter add (@Nonnull final File file) throws IOException
  {
    return add (file.toPath ());
  }

  /**
   * Adds another data object to the ASiC container, using the supplied name as
   * the zip entry name
   *
   * @param file
   *        references the file to be added as a data object.
   * @param entryName
   *        the archive entry name to be used.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of error
   */
  @Nonnull
  default IAsicWriter add (@Nonnull final File file, final String entryName) throws IOException
  {
    return add (file.toPath (), entryName);
  }

  /**
   * Adds another data object to the ASiC archive
   *
   * @param path
   *        references the file to be added.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of an IO error
   * @see #add(File)
   */
  @Nonnull
  default IAsicWriter add (@Nonnull final Path path) throws IOException
  {
    return add (path, path.toFile ().getName ());
  }

  /**
   * Adds another data object to the ASiC container under the entry name
   * provided.
   *
   * @param path
   *        reference to this AsicWriter.
   * @param entryName
   *        the archive entry name to be used.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of an IO error
   * @see #add(File, String)
   */
  @Nonnull
  default IAsicWriter add (@Nonnull final Path path, final String entryName) throws IOException
  {
    try (final InputStream inputStream = Files.newInputStream (path))
    {
      add (inputStream, entryName);
    }
    return this;
  }

  /**
   * Adds the data provided by the stream into the ASiC archive, using the name
   * of the supplied file as the entry name.
   *
   * @param inputStream
   *        input stream of data.
   * @param filename
   *        the name of a file, which must be available in the file system in
   *        order to determine the MIME type.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of an IO error
   */
  @Nonnull
  default IAsicWriter add (@Nonnull @WillNotClose final InputStream inputStream,
                           final String filename) throws IOException
  {
    // Add file to container
    return add (inputStream, filename, AsicUtils.detectMime (filename));
  }

  /**
   * Adds the contents of a file into the ASiC archive using the supplied entry
   * name and MIME type.
   *
   * @param file
   *        references the file to be added as a data object.
   * @param entryName
   *        the archive entry name to be used.
   * @param mimeType
   *        explicitly identifies the MIME type of the entry.
   * @return reference to this AsicWriter
   * @throws IOException
   *         in case of an IO error
   */
  @Nonnull
  default IAsicWriter add (@Nonnull final File file,
                           final String entryName,
                           final IMimeType mimeType) throws IOException
  {
    return add (file.toPath (), entryName, mimeType);
  }

  /**
   * Adds the contents of a file into the ASiC archive using the supplied entry
   * name and MIME type.
   *
   * @param path
   *        references the file to be added as a data object.
   * @param entryName
   *        the archive entry name to be used.
   * @param mimeType
   *        explicitly identifies the MIME type of the entry.
   * @return reference to this AsicWriter
   * @throws IOException
   *         on IO error
   */
  @Nonnull
  default IAsicWriter add (@Nonnull final Path path,
                           final String entryName,
                           final IMimeType mimeType) throws IOException
  {
    try (InputStream inputStream = Files.newInputStream (path))
    {
      add (inputStream, entryName, mimeType);
    }
    return this;
  }

  /**
   * Adds the contents of an input stream into the ASiC archive, under a given
   * entry name and explicitly identifying the MIME type.
   *
   * @param inputStream
   *        Input stream to add
   * @param entryName
   *        the archive entry name to be used.
   * @param mimeType
   *        explicitly identifies the MIME type of the entry.
   * @return reference to this AsicWriter
   * @throws IOException
   *         on IO error
   */
  @Nonnull
  IAsicWriter add (@Nonnull InputStream inputStream, String entryName, IMimeType mimeType) throws IOException;

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
