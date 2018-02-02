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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.annotation.Nonnull;

public abstract class AbstractAsicManifest
{
  protected EMessageDigestAlgorithm m_aMessageDigestAlgorithm;
  protected MessageDigest m_aMD;

  public AbstractAsicManifest (@Nonnull final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    m_aMessageDigestAlgorithm = messageDigestAlgorithm;

    // Create message digest
    try
    {
      m_aMD = MessageDigest.getInstance (messageDigestAlgorithm.getAlgorithm ());
      m_aMD.reset ();
    }
    catch (final NoSuchAlgorithmException e)
    {
      throw new IllegalStateException (String.format ("Algorithm %s not supported",
                                                      messageDigestAlgorithm.getAlgorithm ()),
                                       e);
    }
  }

  @Nonnull
  public MessageDigest getMessageDigest ()
  {
    m_aMD.reset ();
    return m_aMD;
  }

  public abstract void add (String filename, MimeType mimeType);
}
