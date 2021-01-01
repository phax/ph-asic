/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2021 Philip Helger (www.helger.com)
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

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ManifestVerifierTest
{

  private static Logger log = LoggerFactory.getLogger (ManifestVerifierTest.class);

  @Test
  public void validateMessageDigestAlgorithm ()
  {
    final ManifestVerifier manifestVerifier = new ManifestVerifier (EMessageDigestAlgorithm.SHA256);

    // Not to fail
    manifestVerifier.update ("sha256", null, null, EMessageDigestAlgorithm.SHA256.getUri (), null);

    try
    {
      // Should fail
      manifestVerifier.update ("sha384", null, null, EMessageDigestAlgorithm.SHA384.getUri (), null);
      fail ("Exception expected");
    }
    catch (final IllegalArgumentException ex)
    {
      log.info (ex.getMessage ());
    }

    try
    {
      // Should fail
      manifestVerifier.update ("sha512", null, null, EMessageDigestAlgorithm.SHA512.getUri (), null);
      fail ("Exception expected");
    }
    catch (final IllegalArgumentException ex)
    {
      log.info (ex.getMessage ());
    }
  }

  @Test
  public void testValidDigest ()
  {
    final ManifestVerifier manifestVerifier = new ManifestVerifier (EMessageDigestAlgorithm.SHA256);
    manifestVerifier.update ("file", new byte [] { 'c', 'a', 'f', 'e' }, null);
    manifestVerifier.update ("file", "text/plain", new byte [] { 'c', 'a', 'f', 'e' }, null, null);

    // All files is verified
    manifestVerifier.verifyAllVerified ();
  }

  @Test
  public void testInvalidDigest ()
  {
    final ManifestVerifier manifestVerifier = new ManifestVerifier (EMessageDigestAlgorithm.SHA256);
    manifestVerifier.update ("file", new byte [] { 'c', 'a', 'f', 'e' }, null);

    try
    {
      manifestVerifier.update ("file", null, new byte [] { 'c', 'a', 'f', 'f' }, null, null);
      fail ("Exception expected.");
    }
    catch (final IllegalStateException ex)
    {
      log.info (ex.getMessage ());
    }

    try
    {
      manifestVerifier.verifyAllVerified ();
      fail ("Exception expected.");
    }
    catch (final IllegalStateException ex)
    {
      log.info (ex.getMessage ());
    }
  }
}
