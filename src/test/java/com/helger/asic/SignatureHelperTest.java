/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2022 Philip Helger (www.helger.com)
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
import static org.junit.Assert.fail;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.security.keystore.EKeyStoreType;

public final class SignatureHelperTest
{
  private static final Logger LOGGER = LoggerFactory.getLogger (SignatureHelperTest.class);

  @Test
  public void loadNoProblems ()
  {
    assertNotNull (TestUtil.createSH ());
  }

  @SuppressWarnings ("unused")
  @Test
  public void wrongKeystorePassword ()
  {
    try
    {
      new SignatureHelper (EKeyStoreType.JKS,
                           TestUtil.keyStorePathJKS (),
                           TestUtil.keyStorePassword () + "?",
                           TestUtil.keyPairAlias (),
                           TestUtil.privateKeyPassword ());
      fail ("Exception expected.");
    }
    catch (final IllegalStateException ex)
    {
      LOGGER.info ("Expected WrongKeyStorePassword: " + ex.getMessage ());
    }
  }

  @SuppressWarnings ("unused")
  @Test
  public void wrongKeyAlias ()
  {
    try
    {
      new SignatureHelper (EKeyStoreType.JKS,
                           TestUtil.keyStorePathJKS (),
                           TestUtil.keyStorePassword (),
                           TestUtil.keyPairAlias () + "?",
                           TestUtil.privateKeyPassword ());
      fail ("Exception expected.");
    }
    catch (final IllegalStateException ex)
    {
      LOGGER.info ("Expected WrongKeyAlias: " + ex.getMessage ());
    }
  }

  @SuppressWarnings ("unused")
  @Test
  public void wrongKeyPassword ()
  {
    try
    {
      new SignatureHelper (EKeyStoreType.JKS,
                           TestUtil.keyStorePathJKS (),
                           TestUtil.keyStorePassword (),
                           TestUtil.keyPairAlias (),
                           TestUtil.privateKeyPassword () + "?");
      fail ("Exception expected.");
    }
    catch (final IllegalStateException ex)
    {
      LOGGER.info ("Expected WrongKeyPassword: " + ex.getMessage ());
    }
  }
}
