package com.helger.asic;

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OasisManifestTest
{

  private static Logger log = LoggerFactory.getLogger (OasisManifestTest.class);

  @Test
  public void simpleTest ()
  {
    final OasisManifest oasisManifest = new OasisManifest (MimeType.forString (AsicUtils.MIMETYPE_ASICE));
    oasisManifest.add ("test.xml", MimeType.forString ("application/text"));

    log.info (new String (oasisManifest.toBytes ()));
  }

  @SuppressWarnings ("unused")
  @Test
  public void triggerReadException ()
  {
    try
    {
      new OasisManifest (new ByteArrayInputStream ("invalid data".getBytes (StandardCharsets.ISO_8859_1)));
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // Expected
    }
  }

}
