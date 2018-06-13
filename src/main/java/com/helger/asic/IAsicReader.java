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

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.annotation.Nonnull;
import javax.annotation.WillNotClose;

import com.helger.asic.jaxb.asic.AsicManifest;

public interface IAsicReader extends Closeable
{
  /**
   * Provides the name of the next entry in the ASiC archive and positions the
   * inputstream at the beginning of the data.
   *
   * @return name of next entry in archive.
   * @throws IOException
   *         in case of an IO error
   */
  String getNextFile () throws IOException;

  /**
   * Writes the contents of the current entry into a file
   *
   * @param aFile
   *        into which the contents should be written.
   * @throws IOException
   *         in case of an IO error
   */
  default void writeFile (@Nonnull final File aFile) throws IOException
  {
    writeFile (aFile.toPath ());
  }

  /**
   * Writes contents of current archive entry into a file.
   *
   * @param aFile
   *        into which the contents of current entry should be written.
   * @throws IOException
   *         in case of an IO error
   */
  default void writeFile (@Nonnull final Path aFile) throws IOException
  {
    try (final OutputStream outputStream = Files.newOutputStream (aFile))
    {
      writeFile (outputStream);
    }
  }

  /**
   * Writes contents of current archive entry to the supplied output stream.
   *
   * @param aOS
   *        into which data from current entry should be written.
   * @throws IOException
   *         in case of an IO error
   */
  void writeFile (@Nonnull @WillNotClose OutputStream aOS) throws IOException;

  /**
   * Returns InputStream to read the content.
   *
   * @return Content
   * @throws IOException
   *         in case of an IO error
   */
  InputStream inputStream () throws IOException;

  AsicManifest getAsicManifest ();
}
