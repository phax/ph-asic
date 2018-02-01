package no.difi.asic;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

class AsicReaderImpl extends AbstractAsicReader implements IAsicReader
{
  AsicReaderImpl (final EMessageDigestAlgorithm messageDigestAlgorithm,
                  final InputStream inputStream) throws IOException
  {
    super (messageDigestAlgorithm, inputStream);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String getNextFile () throws IOException
  {
    return super.getNextFile ();
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void writeFile (final File file) throws IOException
  {
    writeFile (file.toPath ());
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void writeFile (final Path path) throws IOException
  {
    final OutputStream outputStream = Files.newOutputStream (path);
    writeFile (outputStream);
    outputStream.close ();
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void writeFile (final OutputStream outputStream) throws IOException
  {
    super.writeFile (outputStream);
  }

  @Override
  public InputStream inputStream ()
  {
    return super.inputStream ();
  }
}
