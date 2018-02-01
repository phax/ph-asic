package no.difi.asic;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Stream handling requirements to ASiC files.
 */
class AsicOutputStream extends ZipOutputStream
{
  private static final Logger logger = LoggerFactory.getLogger (AsicOutputStream.class);

  public static final String APPLICATION_VND_ETSI_ASIC_E_ZIP = "application/vnd.etsi.asic-e+zip";

  public AsicOutputStream (final OutputStream aOS) throws IOException
  {
    super (aOS);

    setComment ("mimetype=" + APPLICATION_VND_ETSI_ASIC_E_ZIP);
    _putMimeTypeAsFirstEntry (APPLICATION_VND_ETSI_ASIC_E_ZIP);
  }

  private void _putMimeTypeAsFirstEntry (final String mimeType) throws IOException
  {
    final ZipEntry mimetypeEntry = new ZipEntry ("mimetype");
    mimetypeEntry.setComment ("mimetype=" + mimeType);
    mimetypeEntry.setMethod (ZipEntry.STORED);
    mimetypeEntry.setSize (mimeType.getBytes ().length);

    final CRC32 crc32 = new CRC32 ();
    crc32.update (mimeType.getBytes ());
    mimetypeEntry.setCrc (crc32.getValue ());

    writeZipEntry (mimetypeEntry, mimeType.getBytes ());
  }

  protected void writeZipEntry (final String filename, final byte [] bytes) throws IOException
  {
    writeZipEntry (new ZipEntry (filename), bytes);
  }

  protected void writeZipEntry (final ZipEntry zipEntry, final byte [] bytes) throws IOException
  {
    try
    {
      logger.debug ("Writing entry '{}' to container", zipEntry.getName ());
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
