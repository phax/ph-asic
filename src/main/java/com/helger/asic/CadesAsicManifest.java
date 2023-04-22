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
package com.helger.asic;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.asic.jaxb.ASiCManifestMarshaller;
import com.helger.asic.jaxb.cades.ASiCManifestType;
import com.helger.asic.jaxb.cades.DataObjectReferenceType;
import com.helger.asic.jaxb.cades.SigReferenceType;
import com.helger.commons.base64.Base64;
import com.helger.commons.mime.IMimeType;
import com.helger.xsds.xmldsig.DigestMethodType;

public class CadesAsicManifest extends AbstractAsicManifest
{
  private static final Logger LOGGER = LoggerFactory.getLogger (AbstractAsicManifest.class);

  private final ASiCManifestType m_aManifest = new ASiCManifestType ();
  private boolean m_bRootFilenameIsSet = false;

  public CadesAsicManifest (@Nonnull final EMessageDigestAlgorithm eMDAlgo)
  {
    super (eMDAlgo);
  }

  @Override
  public void add (@Nonnull final String sFilename, @Nonnull final IMimeType aMimeType)
  {
    final DataObjectReferenceType aDataObjectRef = new DataObjectReferenceType ();
    aDataObjectRef.setURI (sFilename);
    aDataObjectRef.setMimeType (aMimeType.getAsString ());
    aDataObjectRef.setDigestValue (internalGetMessageDigest ().digest ());

    final DigestMethodType aDigestMethod = new DigestMethodType ();
    aDigestMethod.setAlgorithm (getMessageDigestAlgorithm ().getUri ());
    aDataObjectRef.setDigestMethod (aDigestMethod);

    m_aManifest.addDataObjectReference (aDataObjectRef);
    if (LOGGER.isDebugEnabled ())
      LOGGER.debug ("Digest: " + Base64.encodeBytes (aDataObjectRef.getDigestValue ()));
  }

  /**
   * Locates the DataObjectReference for the given file name and sets the
   * attribute Rootfile to Boolean.TRUE
   *
   * @param sEntryName
   *        name of entry for which the attribute <code>Rootfile</code> should
   *        be set to "true".
   */
  public void setRootfileForEntry (final String sEntryName)
  {
    if (m_bRootFilenameIsSet)
      throw new IllegalStateException ("Multiple root files are not allowed.");

    for (final DataObjectReferenceType aEntry : m_aManifest.getDataObjectReference ())
      if (aEntry.getURI ().equals (sEntryName))
      {
        aEntry.setRootfile (Boolean.TRUE);
        m_bRootFilenameIsSet = true;
        break;
      }
  }

  public void setSignature (final String sFilename, final String sMimeType)
  {
    final SigReferenceType aSigReference = new SigReferenceType ();
    aSigReference.setURI (sFilename);
    aSigReference.setMimeType (sMimeType);
    m_aManifest.setSigReference (aSigReference);
  }

  @Nonnull
  public ASiCManifestType getASiCManifest ()
  {
    return m_aManifest;
  }

  @Nullable
  public byte [] getAsBytes ()
  {
    return new ASiCManifestMarshaller ().getAsBytes (m_aManifest);
  }

  @Nonnull
  public static String extractAndVerify (final String sXml, final ManifestVerifier aMV)
  {
    // Updating namespaces for compatibility with previous releases and other
    // implementations
    String sRealXML = sXml.replace ("http://uri.etsi.org/02918/v1.1.1#", "http://uri.etsi.org/02918/v1.2.1#");
    sRealXML = sRealXML.replace ("http://uri.etsi.org/2918/v1.2.1#", "http://uri.etsi.org/02918/v1.2.1#");
    sRealXML = sRealXML.replace ("http://www.w3.org/2000/09/xmldsig#sha", "http://www.w3.org/2001/04/xmlenc#sha");

    // Read XML
    final ASiCManifestType aManifest = new ASiCManifestMarshaller ().read (sRealXML);
    if (aManifest == null)
      throw new IllegalStateException ("Unable to read content as XML");

    String sSigReference = aManifest.getSigReference ().getURI ();
    if (sSigReference == null)
      sSigReference = "META-INF/signature.p7s";

    // Run through recorded objects
    for (final DataObjectReferenceType aDOR : aManifest.getDataObjectReference ())
    {
      aMV.update (aDOR.getURI (),
                  aDOR.getMimeType (),
                  aDOR.getDigestValue (),
                  aDOR.getDigestMethod ().getAlgorithm (),
                  sSigReference);
      if (aDOR.isRootfile () == Boolean.TRUE)
        aMV.setRootFilename (aDOR.getURI ());
    }

    return sSigReference;
  }
}
