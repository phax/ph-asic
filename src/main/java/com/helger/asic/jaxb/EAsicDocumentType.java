/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2023 Philip Helger (www.helger.com)
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

import javax.annotation.Nonnull;
import javax.xml.validation.Schema;

import com.helger.asic.jaxb.cades.ASiCManifestType;
import com.helger.asic.jaxb.opendocument.manifest.Manifest;
import com.helger.commons.annotation.Nonempty;
import com.helger.commons.annotation.ReturnsMutableCopy;
import com.helger.commons.collection.impl.CommonsArrayList;
import com.helger.commons.collection.impl.ICommonsList;
import com.helger.commons.io.resource.ClassPathResource;
import com.helger.commons.string.StringHelper;
import com.helger.jaxb.builder.IJAXBDocumentType;
import com.helger.jaxb.builder.JAXBDocumentType;
import com.helger.xsds.xmldsig.CXMLDSig;

/**
 * Enumeration with all available ASIC document types.
 *
 * @author Philip Helger
 */
public enum EAsicDocumentType implements IJAXBDocumentType
{
  ASIC_MANIFEST (ASiCManifestType.class,
                 new CommonsArrayList <> (CXMLDSig.getXSDResource (),
                                          new ClassPathResource ("/schemas/ts_102918v010201.xsd", _getCL ()))),
  OASIS_MANIFEST (Manifest.class,
                  new CommonsArrayList <> (new ClassPathResource ("/schemas/OpenDocument_manifest.xsd", _getCL ())));

  @Nonnull
  private static final ClassLoader _getCL ()
  {
    return EAsicDocumentType.class.getClassLoader ();
  }

  private final JAXBDocumentType m_aDocType;

  private EAsicDocumentType (@Nonnull final Class <?> aClass, @Nonnull final List <ClassPathResource> aXSDPath)
  {
    m_aDocType = new JAXBDocumentType (aClass, aXSDPath, x -> StringHelper.trimEnd (x, "Type"));
  }

  @Nonnull
  public Class <?> getImplementationClass ()
  {
    return m_aDocType.getImplementationClass ();
  }

  @Nonnull
  @Nonempty
  @ReturnsMutableCopy
  public ICommonsList <ClassPathResource> getAllXSDResources ()
  {
    return m_aDocType.getAllXSDResources ();
  }

  @Nonnull
  public String getNamespaceURI ()
  {
    return m_aDocType.getNamespaceURI ();
  }

  @Nonnull
  @Nonempty
  public String getLocalName ()
  {
    return m_aDocType.getLocalName ();
  }

  @Nonnull
  public Schema getSchema ()
  {
    return m_aDocType.getSchema ();
  }
}
