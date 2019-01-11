/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2019 Philip Helger (www.helger.com)
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
import java.io.OutputStream;

import javax.annotation.Nonnull;
import javax.annotation.WillCloseWhenClosed;

public class AsicReaderImpl extends AbstractAsicReader implements IAsicReader
{
  protected AsicReaderImpl (@Nonnull final EMessageDigestAlgorithm eMDAlgo,
                            @Nonnull @WillCloseWhenClosed final InputStream aIS)
  {
    super (eMDAlgo, aIS);
  }

  @Override
  public void writeFile (@Nonnull final OutputStream aOS) throws IOException
  {
    super.internalWriteFile (aOS);
  }

  @Override
  @Nonnull
  public InputStream inputStream ()
  {
    return super.internalInputStream ();
  }
}
