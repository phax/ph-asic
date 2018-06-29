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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import org.junit.Test;

import com.helger.security.keystore.EKeyStoreType;

public final class SignatureHelperTest
{
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
      new SignatureHelper (EKeyStoreType.JKS,
                           TestUtil.keyStorePathJKS (),
                           TestUtil.keyStorePassword (),
                           TestUtil.keyPairAlias (),
                           TestUtil.privateKeyPassword () + "?");
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
      new SignatureHelper (EKeyStoreType.JKS,
                           TestUtil.keyStorePathJKS (),
                           TestUtil.keyStorePassword (),
                           TestUtil.keyPairAlias () + "?",
                           TestUtil.privateKeyPassword ());
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // Ignore
    }
  }
}
