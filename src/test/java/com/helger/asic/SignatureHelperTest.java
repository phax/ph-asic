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

import static org.junit.Assert.fail;

import org.junit.Test;

import com.helger.commons.io.resource.ClassPathResource;

public final class SignatureHelperTest
{
  @SuppressWarnings ("unused")
  @Test
  public void loadNoProblems ()
  {
    new SignatureHelper (ClassPathResource.getInputStream ("/asic/keystore.jks"), "changeit", null, "changeit");
  }

  @SuppressWarnings ("unused")
  @Test
  public void wrongKeystorePassword ()
  {
    try
    {
      new SignatureHelper (ClassPathResource.getInputStream ("/asic/keystore.jks"), "changed?", null, "changeit");
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // Ignore
    }
  }

  @SuppressWarnings ("unused")
  @Test
  public void wrongKeyPassword ()
  {
    try
    {
      new SignatureHelper (ClassPathResource.getInputStream ("/asic/keystore.jks"), "changeit", null, "changed?");
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // Ignore
    }
  }

  @SuppressWarnings ("unused")
  @Test
  public void wrongKeyAlias ()
  {
    try
    {
      new SignatureHelper (ClassPathResource.getInputStream ("/asic/keystore.jks"), "changeit", "asic", "changeit");
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // Ignore
    }
  }
}
