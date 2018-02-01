package com.helger.asic;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Test;

import com.helger.commons.io.stream.NullOutputStream;

/**
 * Testing functionality.
 */
public class AsicReaderTest
{

  private final AsicReaderFactory asicReaderFactory = AsicReaderFactory.newFactory ();

  @Test
  public void readingContentWithWriteFile () throws IOException
  {
    // Testing using AsicReader::writeFile.
    final IAsicReader asicReader = asicReaderFactory.open (getClass ().getResourceAsStream ("/asic-cades-test-valid.asice"));
    while (asicReader.getNextFile () != null)
      asicReader.writeFile (new NullOutputStream ());
    asicReader.close ();
    assertEquals (1, asicReader.getAsicManifest ().getCertificate ().size ());
  }

  @Test
  public void readingContentWithInputStream () throws IOException
  {
    // Testing using AsicReader::inputStream.
    final IAsicReader asicReader = asicReaderFactory.open (getClass ().getResourceAsStream ("/asic-cades-test-valid.asice"));
    while (asicReader.getNextFile () != null)
      AsicUtils.copyStream (asicReader.inputStream (), new NullOutputStream ());
    asicReader.close ();
    assertEquals (1, asicReader.getAsicManifest ().getCertificate ().size ());
  }

  @Test
  public void readingContentWithoutReading () throws IOException
  {
    // Testing using no functionality to read content.
    final IAsicReader asicReader = asicReaderFactory.open (getClass ().getResourceAsStream ("/asic-cades-test-valid.asice"));
    while (asicReader.getNextFile () != null)
    {
      // No action
    }
    asicReader.close ();
    assertEquals (1, asicReader.getAsicManifest ().getCertificate ().size ());
  }

  @Test (expected = IllegalStateException.class)
  public void exceptionOnEmpty () throws IOException
  {
    final IAsicReader asicReader = asicReaderFactory.open (getClass ().getResourceAsStream ("/asic-cades-test-valid.asice"));
    while (asicReader.getNextFile () != null)
      asicReader.writeFile (new NullOutputStream ());

    // Trigger exception.
    asicReader.inputStream ();

    fail ("Exception not triggered.");
  }
}