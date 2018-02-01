package com.helger.asic;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class AsicReaderImpl extends AbstractAsicReader implements IAsicReader
{
  protected AsicReaderImpl (final EMessageDigestAlgorithm messageDigestAlgorithm, final InputStream inputStream)
  {
    super (messageDigestAlgorithm, inputStream);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void writeFile (final OutputStream outputStream) throws IOException
  {
    super.internalWriteFile (outputStream);
  }

  @Override
  public InputStream inputStream ()
  {
    return super.internalInputStream ();
  }
}
