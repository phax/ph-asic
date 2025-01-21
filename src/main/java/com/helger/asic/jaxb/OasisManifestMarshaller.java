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

import javax.xml.namespace.QName;

import com.helger.asic.OasisManifest;
import com.helger.asic.jaxb.opendocument.manifest.Manifest;
import com.helger.commons.collection.impl.CommonsArrayList;
import com.helger.commons.io.resource.ClassPathResource;
import com.helger.jaxb.GenericJAXBMarshaller;
import com.helger.xml.namespace.MapBasedNamespaceContext;
import com.helger.xsds.xmldsig.CXMLDSig;

/**
 * JAXB marshaller for the {@link Manifest}.
 *
 * @author Philip Helger
 * @since 3.0.0
 */
public class OasisManifestMarshaller extends GenericJAXBMarshaller <Manifest>
{
  public static final List <ClassPathResource> XSDS = new CommonsArrayList <> (CXMLDSig.getXSDResource (),
                                                                               new ClassPathResource ("external/schemas/OpenDocument_manifest.xsd",
                                                                                                      OasisManifestMarshaller.class.getClassLoader ())).getAsUnmodifiable ();

  private static final QName QN = new QName ("urn:oasis:names:tc:opendocument:xmlns:manifest:1.0", "manifest");

  private static final MapBasedNamespaceContext NSCTX = new MapBasedNamespaceContext ();
  static
  {
    // Not default namespace because attribute form is qualified!
    NSCTX.addMapping ("manifest", OasisManifest.NAMESPACE_URI);
  }

  public OasisManifestMarshaller ()
  {
    super (Manifest.class, null, createSimpleJAXBElement (QN, Manifest.class));
    setNamespaceContext (NSCTX.getClone ());
    setFormattedOutput (true);
  }
}
