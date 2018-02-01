package com.helger.asic;

import org.junit.Test;

public class CadesAsicManifestTest
{

  @Test (expected = IllegalStateException.class)
  public void multipleRootFiles ()
  {
    final CadesAsicManifest manifest = new CadesAsicManifest (EMessageDigestAlgorithm.SHA256);
    manifest.add ("testfile1.xml", MimeType.XML);
    manifest.add ("testfile2.xml", MimeType.XML);

    manifest.setRootfileForEntry ("testfile1.xml");
    manifest.setRootfileForEntry ("testfile2.xml");
  }
}
