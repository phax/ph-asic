package com.helger.asic;

import java.security.Provider;
import java.security.Security;

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

  public static Provider getProvider ()
  {
    return PROVIDER;
  }
}
