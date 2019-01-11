/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2019 Philip Helger (www.helger.com)
 * philip[at]helger[dot]com
 *
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/
 */
package com.helger.asic;

import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.io.stream.NonBlockingByteArrayInputStream;
import com.helger.commons.mime.CMimeType;

public final class OasisManifestTest
{
  private static final Logger log = LoggerFactory.getLogger (OasisManifestTest.class);

  @Test
  public void simpleTest ()
  {
    final OasisManifest oasisManifest = new OasisManifest (AsicUtils.MIMETYPE_ASICE);
    oasisManifest.add ("test.xml", CMimeType.APPLICATION_XML);

    log.info (oasisManifest.getAsString ());
  }

  @SuppressWarnings ("unused")
  @Test
  public void triggerReadException ()
  {
    try
    {
      new OasisManifest (new NonBlockingByteArrayInputStream ("invalid data".getBytes (StandardCharsets.ISO_8859_1)));
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // Expected
    }
  }

}
