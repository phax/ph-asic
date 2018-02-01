package com.helger.asic;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.io.stream.NonBlockingByteArrayOutputStream;

public class AsicInputStream extends ZipInputStream
{
  private static final Logger logger = LoggerFactory.getLogger (AsicInputStream.class);

  public AsicInputStream (final InputStream aIS)
  {
    super (aIS);
  }

  @Override
  public ZipEntry getNextEntry () throws IOException
  {
    ZipEntry zipEntry = super.getNextEntry ();

    if (zipEntry != null && zipEntry.getName ().equals ("mimetype"))
    {
      final NonBlockingByteArrayOutputStream baos = new NonBlockingByteArrayOutputStream ();
      AsicUtils.copyStream (this, baos);
      final String sMimeType = baos.getAsString (StandardCharsets.ISO_8859_1);

      if (logger.isDebugEnabled ())
        logger.debug ("Content of mimetype: " + sMimeType);
      if (!AsicUtils.MIMETYPE_ASICE.equals (sMimeType))
        throw new IllegalStateException ("Content is not ASiC-E container.");

      // Fetch next
      zipEntry = super.getNextEntry ();
    }

    return zipEntry;
  }
}
