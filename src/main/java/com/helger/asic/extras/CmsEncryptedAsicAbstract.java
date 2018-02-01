package com.helger.asic.extras;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

abstract class CmsEncryptedAsicAbstract
{

  protected static final String BC = BouncyCastleProvider.PROVIDER_NAME;

  static
  {
    if (Security.getProvider (BouncyCastleProvider.PROVIDER_NAME) == null)
      Security.addProvider (new BouncyCastleProvider ());
  }
}
