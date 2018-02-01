package com.helger.asic;

import java.io.File;

import com.helger.commons.io.resource.ClassPathResource;

/**
 * @author steinar Date: 21.07.15 Time: 18.48
 */
public final class TestUtil
{
  public static final String KEY_STORE_RESOURCE_NAME = "keystore.jks";
  public static final String BII_SAMPLE_MESSAGE_XML = "bii-trns081.xml";

  /**
   * Provides simple access to the KeyStore file provided as part of the
   * distribution.
   * <p/>
   * The key store provides a private key and a certificate, which is used for
   * testing purposes.
   *
   * @return File
   */
  public static File keyStoreFile ()
  {
    return new ClassPathResource (KEY_STORE_RESOURCE_NAME).getAsFile ();
  }

  public static String keyStorePassword ()
  {
    return "changeit";
  }

  public static String privateKeyPassword ()
  {
    return "changeit";
  }

  public static String keyPairAlias ()
  {
    return "selfsigned";
  }
}
