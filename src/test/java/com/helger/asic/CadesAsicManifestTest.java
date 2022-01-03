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

import org.junit.Test;

import com.helger.commons.mime.CMimeType;

public final class CadesAsicManifestTest
{
  @Test (expected = IllegalStateException.class)
  public void multipleRootFiles ()
  {
    final CadesAsicManifest manifest = new CadesAsicManifest (EMessageDigestAlgorithm.SHA256);
    manifest.add ("testfile1.xml", CMimeType.APPLICATION_XML);
    manifest.add ("testfile2.xml", CMimeType.APPLICATION_XML);

    manifest.setRootfileForEntry ("testfile1.xml");
    manifest.setRootfileForEntry ("testfile2.xml");
  }
}
