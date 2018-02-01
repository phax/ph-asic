package no.difi.asic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class AsicInputStream extends ZipInputStream
{
  private static final Logger logger = LoggerFactory.getLogger (AsicInputStream.class);

  public AsicInputStream (final InputStream in)
  {
    super (in);
  }

  @Override
  public ZipEntry getNextEntry () throws IOException
  {
    ZipEntry zipEntry = super.getNextEntry ();

    if (zipEntry != null && zipEntry.getName ().equals ("mimetype"))
    {
      final ByteArrayOutputStream baos = new ByteArrayOutputStream ();
      AsicUtils.copyStream (this, baos);

      logger.debug ("Content of mimetype: {}", baos.toString ());
      if (!AsicUtils.MIMETYPE_ASICE.equals (baos.toString ()))
        throw new IllegalStateException ("Content is not ASiC-E container.");

      // Fetch next
      zipEntry = super.getNextEntry ();
    }

    return zipEntry;
  }
}
