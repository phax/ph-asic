/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2025 Philip Helger (www.helger.com)
 * philip[at]helger[dot]com
 *
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/
 */
package com.helger.asic;

import static org.junit.Assert.assertNotNull;

import java.io.InputStream;

import javax.annotation.Nonnull;

import com.helger.commons.io.stream.StreamHelper;
import com.helger.security.keystore.EKeyStoreType;
import com.helger.security.keystore.KeyStoreHelper;

/**
 * @author steinar Date: 21.07.15 Time: 18.48
 */
public final class TestUtil
{
  public static final String KEY_STORE_RESOURCE_NAME = "external/asic/keystore.jks";
  public static final String BII_SAMPLE_MESSAGE_XML = "external/asic/bii-trns081.xml";

  private TestUtil ()
  {}

  static
  {
    final InputStream aIS = KeyStoreHelper.getResourceProvider ().getInputStream (KEY_STORE_RESOURCE_NAME);
    try
    {
      assertNotNull ("No such keystore: " + KEY_STORE_RESOURCE_NAME, aIS);
    }
    finally
    {
      StreamHelper.close (aIS);
    }
  }

  /**
   * Provides simple access to the KeyStore file provided as part of the
   * distribution.
   * <p/>
   * The key store provides a private key and a certificate, which is used for
   * testing purposes.
   *
   * @return JKS key store path
   */
  @Nonnull
  public static String keyStorePathJKS ()
  {
    return KEY_STORE_RESOURCE_NAME;
  }

  @Nonnull
  public static char [] keyStorePassword ()
  {
    return "changeit".toCharArray ();
  }

  @Nonnull
  public static String keyPairAlias ()
  {
    return "selfsigned";
  }

  @Nonnull
  public static char [] privateKeyPassword ()
  {
    return "changeit".toCharArray ();
  }

  @Nonnull
  public static SignatureHelper createSH ()
  {
    return new SignatureHelper (EKeyStoreType.JKS, keyStorePathJKS (), keyStorePassword (), keyPairAlias (), privateKeyPassword ());
  }
}
