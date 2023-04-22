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

import com.helger.asic.jaxb.cades.ASiCManifestType;
import com.helger.asic.jaxb.opendocument.manifest.Manifest;
import com.helger.jaxb.builder.JAXBReaderBuilder;

/**
 * A reader builder for Asic documents.
 *
 * @author Philip Helger
 * @param <JAXBTYPE>
 *        The Asic implementation class to be read
 */
@NotThreadSafe
@Deprecated (since = "3.0.0", forRemoval = true)
public class AsicReader <JAXBTYPE> extends JAXBReaderBuilder <JAXBTYPE, AsicReader <JAXBTYPE>>
{
  public AsicReader (@Nonnull final EAsicDocumentType eDocType, @Nonnull final Class <JAXBTYPE> aImplClass)
  {
    super (eDocType, aImplClass);
  }

  /**
   * Create a reader builder for ASiCManifestType.
   *
   * @return The builder and never <code>null</code>
   */
  @Nonnull
  public static AsicReader <ASiCManifestType> asicManifest ()
  {
    return new AsicReader <> (EAsicDocumentType.ASIC_MANIFEST, ASiCManifestType.class);
  }

  /**
   * Create a reader builder for Manifest.
   *
   * @return The builder and never <code>null</code>
   */
  @Nonnull
  public static AsicReader <Manifest> oasisManifest ()
  {
    return new AsicReader <> (EAsicDocumentType.OASIS_MANIFEST, Manifest.class);
  }
}
