/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2023 Philip Helger (www.helger.com)
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
import java.security.DigestOutputStream;
import java.security.MessageDigest;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.base64.Base64;
import com.helger.commons.io.resource.ClassPathResource;
import com.helger.commons.io.stream.NullOutputStream;

/**
 * @author steinar Date: 03.07.15 Time: 14.47
 */
public final class SignatureTest
{
  private static final Logger LOG = LoggerFactory.getLogger (SignatureTest.class);

  @Test
  public void createSampleDigest () throws Exception
  {
    try (final InputStream is = ClassPathResource.getInputStream (TestUtil.BII_SAMPLE_MESSAGE_XML))
    {
      assertNotNull (is);

      final MessageDigest aMD = MessageDigest.getInstance ("SHA-256");
      try (final DigestOutputStream outputStream = new DigestOutputStream (new NullOutputStream (), aMD))
      {
        int c;
        while ((c = is.read ()) > -1)
        {
          outputStream.write (c);
        }
      }

      final byte [] digest = aMD.digest ();
      if (LOG.isDebugEnabled ())
        LOG.debug (Base64.encodeBytes (digest));
    }
  }
}
