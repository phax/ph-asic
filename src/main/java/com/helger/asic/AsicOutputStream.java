package com.helger.asic;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.annotation.Nonempty;

/**
 * Stream handling requirements to ASiC files.
 */
public class AsicOutputStream extends ZipOutputStream
{
  private static final Logger logger = LoggerFactory.getLogger (AsicOutputStream.class);

  public AsicOutputStream (final OutputStream aOS) throws IOException
  {
    super (aOS);

    setComment ("mimetype=" + AsicUtils.MIMETYPE_ASICE);
    _putMimeTypeAsFirstEntry (AsicUtils.MIMETYPE_ASICE);
  }

  private void _putMimeTypeAsFirstEntry (@Nonnull @Nonempty final String sMimeType) throws IOException
  {
    final ZipEntry mimetypeEntry = new ZipEntry ("mimetype");
    mimetypeEntry.setComment ("mimetype=" + sMimeType);
    mimetypeEntry.setMethod (ZipEntry.STORED);

    final byte [] aContentBytes = sMimeType.getBytes (StandardCharsets.ISO_8859_1);
    mimetypeEntry.setSize (aContentBytes.length);

    final CRC32 crc32 = new CRC32 ();
    crc32.update (aContentBytes);
    mimetypeEntry.setCrc (crc32.getValue ());

    writeZipEntry (mimetypeEntry, aContentBytes);
  }

  protected void writeZipEntry (final String filename, final byte [] bytes) throws IOException
  {
    writeZipEntry (new ZipEntry (filename), bytes);
  }

  protected void writeZipEntry (final ZipEntry zipEntry, final byte [] bytes) throws IOException
  {
    try
    {
      if (logger.isDebugEnabled ())
        logger.debug ("Writing entry '" + zipEntry.getName () + "' to container");
      putNextEntry (zipEntry);
      write (bytes);
      closeEntry ();
    }
    catch (final IOException e)
    {
      throw new IOException ("Unable to create new ZIP entry for " + zipEntry.getName (), e);
    }
  }
}
