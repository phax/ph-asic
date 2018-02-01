package com.helger.asic;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import com.helger.asic.jaxb.asic.AsicManifest;

public interface IAsicReader extends Closeable
{
  /**
   * Provides the name of the next entry in the ASiC archive and positions the
   * inputstream at the beginning of the data.
   *
   * @return name of next entry in archive.
   * @throws IOException
   */
  String getNextFile () throws IOException;

  /**
   * Writes the contents of the current entry into a file
   *
   * @param file
   *        into which the contents should be written.
   * @throws IOException
   */
  default void writeFile (final File file) throws IOException
  {
    writeFile (file.toPath ());
  }

  /**
   * Writes contents of current archive entry into a file.
   *
   * @param path
   *        into which the contents of current entry should be written.
   * @throws IOException
   */
  default void writeFile (final Path path) throws IOException
  {
    try (final OutputStream outputStream = Files.newOutputStream (path))
    {
      writeFile (outputStream);
    }
  }

  /**
   * Writes contents of current archive entry to the supplied output stream.
   *
   * @param outputStream
   *        into which data from current entry should be written.
   * @throws IOException
   */
  void writeFile (OutputStream outputStream) throws IOException;

  /**
   * Returns InputStream to read the content.
   *
   * @return Content
   * @throws IOException
   */
  InputStream inputStream () throws IOException;

  AsicManifest getAsicManifest ();
}
