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

import java.security.Provider;
import java.security.Security;

import javax.annotation.Nonnull;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author erlend
 */
public final class BCHelper
{
  private static final Provider PROVIDER;

  static
  {
    Provider p = Security.getProvider (BouncyCastleProvider.PROVIDER_NAME);
    if (p != null)
    {
      PROVIDER = p;
    }
    else
    {
      PROVIDER = p = new BouncyCastleProvider ();
      Security.addProvider (PROVIDER);
    }
  }

  @Nonnull
  public static Provider getProvider ()
  {
    return PROVIDER;
  }
}
