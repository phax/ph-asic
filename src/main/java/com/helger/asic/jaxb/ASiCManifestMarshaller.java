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
package com.helger.asic.jaxb;

import java.util.List;

import com.helger.asic.jaxb.cades.ASiCManifestType;
import com.helger.asic.jaxb.cades.ObjectFactory;
import com.helger.collection.commons.CommonsArrayList;
import com.helger.io.resource.ClassPathResource;
import com.helger.jaxb.GenericJAXBMarshaller;
import com.helger.xsds.xmldsig.CXMLDSig;

/**
 * JAXB marshaller for the {@link ASiCManifestType}.
 *
 * @author Philip Helger
 * @since 3.0.0
 */
public class ASiCManifestMarshaller extends GenericJAXBMarshaller <ASiCManifestType>
{
  public static final List <ClassPathResource> XSDS = new CommonsArrayList <> (CXMLDSig.getXSDResource (),
                                                                               new ClassPathResource ("external/schemas/ts_102918v010201.xsd",
                                                                                                      ASiCManifestMarshaller.class.getClassLoader ())).getAsUnmodifiable ();

  public ASiCManifestMarshaller ()
  {
    super (ASiCManifestType.class, XSDS, new ObjectFactory ()::createASiCManifest);
    setFormattedOutput (true);
  }
}
