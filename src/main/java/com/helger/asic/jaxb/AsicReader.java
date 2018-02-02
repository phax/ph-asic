/**
 * Copyright (C) 2016-2018 Philip Helger (www.helger.com)
 * philip[at]helger[dot]com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
    return new AsicReader <> (EAsicDocumentType.MANIFEST, Manifest.class);
  }
}
