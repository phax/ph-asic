package com.helger.asic;

import java.io.IOException;
import java.io.InputStream;

import com.helger.commons.io.stream.NullOutputStream;

public class AsicVerifier extends AbstractAsicReader
{
  AsicVerifier (final EMessageDigestAlgorithm messageDigestAlgorithm, final InputStream inputStream) throws IOException
  {
    super (messageDigestAlgorithm, inputStream);

    while (getNextFile () != null)
      internalWriteFile (new NullOutputStream ());

    close ();
  }
}
