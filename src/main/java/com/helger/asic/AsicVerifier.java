/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2025 Philip Helger (www.helger.com)
 * philip[at]helger[dot]com
 *
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/
 */
package com.helger.asic;

import java.io.IOException;
import java.io.InputStream;

import org.jspecify.annotations.NonNull;

import com.helger.annotation.WillClose;
import com.helger.base.io.stream.NullOutputStream;

public class AsicVerifier extends AbstractAsicReader
{
  protected AsicVerifier (@NonNull final EMessageDigestAlgorithm eMDAlgo,
                          @NonNull @WillClose final InputStream aIS) throws IOException
  {
    super (eMDAlgo, aIS);

    try
    {
      while (getNextFile () != null)
        internalWriteFile (new NullOutputStream ());
    }
    finally
    {
      close ();
    }
  }
}
