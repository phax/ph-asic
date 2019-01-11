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
package com.helger.asic.jaxb;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.NotThreadSafe;

import com.helger.asic.jaxb.cades.ASiCManifestType;
import com.helger.asic.jaxb.opendocument.manifest.Manifest;
import com.helger.jaxb.builder.JAXBValidationBuilder;

/**
 * A validator builder for Asic documents.
 *
 * @author Philip Helger
 * @param <JAXBTYPE>
 *        The Asic implementation class to be read
 */
@NotThreadSafe
public class AsicValidator <JAXBTYPE> extends JAXBValidationBuilder <JAXBTYPE, AsicValidator <JAXBTYPE>>
{
  public AsicValidator (@Nonnull final EAsicDocumentType eDocType)
  {
    super (eDocType);
  }

  /**
   * Create a validator builder for ASiCManifestType.
   *
   * @return The builder and never <code>null</code>
   */
  @Nonnull
  public static AsicValidator <ASiCManifestType> asicManifest ()
  {
    return new AsicValidator <> (EAsicDocumentType.ASIC_MANIFEST);
  }

  /**
   * Create a validator builder for Manifest.
   *
   * @return The builder and never <code>null</code>
   */
  @Nonnull
  public static AsicValidator <Manifest> oasisManifest ()
  {
    return new AsicValidator <> (EAsicDocumentType.MANIFEST);
  }
}
