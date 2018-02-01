package no.difi.asic;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author erlend
 */
class BCHelper
{

  private static final Provider PROVIDER;

  static
  {
    if (Security.getProvider (BouncyCastleProvider.PROVIDER_NAME) != null)
    {
      PROVIDER = Security.getProvider (BouncyCastleProvider.PROVIDER_NAME);
    }
    else
    {
      PROVIDER = new BouncyCastleProvider ();
      Security.addProvider (PROVIDER);
    }
  }

  public static Provider getProvider ()
  {
    return PROVIDER;
  }
}
