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

import javax.annotation.Nonnull;
import javax.annotation.concurrent.NotThreadSafe;

import com.helger.asic.OasisManifest;
import com.helger.asic.jaxb.cades.ASiCManifestType;
import com.helger.asic.jaxb.opendocument.manifest.Manifest;
import com.helger.jaxb.builder.JAXBWriterBuilder;
import com.helger.xml.namespace.MapBasedNamespaceContext;

/**
 * A writer builder for Asic documents.
 *
 * @author Philip Helger
 * @param <JAXBTYPE>
 *        The Asic implementation class to be read
 */
@NotThreadSafe
public class AsicWriter <JAXBTYPE> extends JAXBWriterBuilder <JAXBTYPE, AsicWriter <JAXBTYPE>>
{
  public AsicWriter (@Nonnull final EAsicDocumentType eDocType)
  {
    super (eDocType);
  }

  /**
   * Create a writer builder for ASiCManifestType.
   *
   * @return The builder and never <code>null</code>
   */
  @Nonnull
  public static AsicWriter <ASiCManifestType> asicManifest ()
  {
    final AsicWriter <ASiCManifestType> ret = new AsicWriter <> (EAsicDocumentType.ASIC_MANIFEST);
    ret.setFormattedOutput (true);
    return ret;
  }

  /**
   * Create a writer builder for Manifest.
   *
   * @return The builder and never <code>null</code>
   */
  @Nonnull
  public static AsicWriter <Manifest> oasisManifest ()
  {
    final AsicWriter <Manifest> ret = new AsicWriter <> (EAsicDocumentType.OASIS_MANIFEST);
    final MapBasedNamespaceContext aCtx = new MapBasedNamespaceContext ();
    // Not default namespace because attribute form is qualified!
    aCtx.addMapping ("manifest", OasisManifest.NAMESPACE_URI);
    ret.setNamespaceContext (aCtx);
    ret.setFormattedOutput (true);
    return ret;
  }
}
