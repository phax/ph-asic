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

import java.nio.charset.StandardCharsets;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.asic.jaxb.ASiCManifestMarshaller;
import com.helger.asic.jaxb.cades.ASiCManifestType;
import com.helger.asic.jaxb.cades.DataObjectReferenceType;
import com.helger.asic.jaxb.cades.SigReferenceType;
import com.helger.xsds.xmldsig.DigestMethodType;

/**
 * @author steinar Date: 03.07.15 Time: 09.09
 */
public final class AsicManifestReferenceTest
{
  private static final Logger LOGGER = LoggerFactory.getLogger (AsicManifestReferenceTest.class);

  @Test
  public void createSampleManifest () throws Exception
  {
    final ASiCManifestType asicManifest = new ASiCManifestType ();

    final SigReferenceType sigReferenceType = new SigReferenceType ();
    // TODO: implement signature
    sigReferenceType.setURI ("META-INF/signature.p7s");
    // TODO: use strong typed Mime types
    sigReferenceType.setMimeType ("application/x-pkcs7-signature");
    asicManifest.setSigReference (sigReferenceType);

    {
      final DataObjectReferenceType obj1 = new DataObjectReferenceType ();
      // TODO: retrieve doc name from container
      obj1.setURI ("bii-envelope.xml");
      obj1.setMimeType ("application/xml");

      final DigestMethodType digestMethodType = new DigestMethodType ();
      digestMethodType.setAlgorithm ("http://www.w3.org/2001/04/xmlenc#sha256");
      obj1.setDigestMethod (digestMethodType);
      obj1.setDigestValue ("j61wx3SAvKTMUP4NbeZ1".getBytes (StandardCharsets.ISO_8859_1));

      asicManifest.getDataObjectReference ().add (obj1);
    }

    {
      final DataObjectReferenceType obj2 = new DataObjectReferenceType ();
      obj2.setURI ("bii-document.xml");
      obj2.setMimeType ("application/xml");

      final DigestMethodType digestMethodType = new DigestMethodType ();
      digestMethodType.setAlgorithm ("http://www.w3.org/2001/04/xmlenc#sha256");
      obj2.setDigestMethod (digestMethodType);
      obj2.setDigestValue ("j61wx3SAvKTMUP4NbeZ1".getBytes (StandardCharsets.ISO_8859_1));

      asicManifest.getDataObjectReference ().add (obj2);
    }

    LOGGER.info (new ASiCManifestMarshaller ().getAsString (asicManifest));
  }
}
