/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018 Philip Helger (www.helger.com)
 * philip[at]helger[dot]com
 *
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/
 */
package com.helger.asic;

import java.io.File;

import javax.annotation.Nonnull;

import com.helger.commons.io.resource.ClassPathResource;

/**
 * @author steinar Date: 21.07.15 Time: 18.48
 */
public final class TestUtil
{
  public static final String KEY_STORE_RESOURCE_NAME = "/asic/keystore.jks";
  public static final String BII_SAMPLE_MESSAGE_XML = "/asic/bii-trns081.xml";

  private TestUtil ()
  {}

  /**
   * Provides simple access to the KeyStore file provided as part of the
   * distribution.
   * <p/>
   * The key store provides a private key and a certificate, which is used for
   * testing purposes.
   *
   * @return File
   */
  @Nonnull
  public static File keyStoreFile ()
  {
    return ClassPathResource.getAsFile (KEY_STORE_RESOURCE_NAME);
  }

  @Nonnull
  public static String keyStorePassword ()
  {
    return "changeit";
  }

  @Nonnull
  public static String keyPairAlias ()
  {
    return "selfsigned";
  }

  @Nonnull
  public static String privateKeyPassword ()
  {
    return "changeit";
  }
}
