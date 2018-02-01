package no.difi.asic;

import java.io.IOException;
import java.io.InputStream;

import com.helger.commons.io.stream.NullOutputStream;

public class AsicVerifier extends AbstractAsicReader
{
  AsicVerifier (final MessageDigestAlgorithm messageDigestAlgorithm, final InputStream inputStream) throws IOException
  {
    super (messageDigestAlgorithm, inputStream);

    while (getNextFile () != null)
      writeFile (new NullOutputStream ());

    close ();
  }
}
