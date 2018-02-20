/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018 Philip Helger (www.helger.com)
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

import com.helger.asic.jaxb.AsicReader;
import com.helger.asic.jaxb.AsicWriter;
import com.helger.asic.jaxb.cades.ASiCManifestType;
import com.helger.asic.jaxb.cades.DataObjectReferenceType;
import com.helger.asic.jaxb.cades.SigReferenceType;
import com.helger.commons.base64.Base64;
import com.helger.commons.mime.IMimeType;
import com.helger.xsds.xmldsig.DigestMethodType;

public class CadesAsicManifest extends AbstractAsicManifest
{
  private static final Logger LOG = LoggerFactory.getLogger (AbstractAsicManifest.class);

  private final ASiCManifestType m_aManifest = new ASiCManifestType ();
  private boolean m_bRootFilenameIsSet = false;

  public CadesAsicManifest (@Nonnull final EMessageDigestAlgorithm eMDAlgo)
  {
    super (eMDAlgo);
  }

  @Override
  public void add (@Nonnull final String sFilename, @Nonnull final IMimeType aMimeType)
  {
    final DataObjectReferenceType dataObject = new DataObjectReferenceType ();
    dataObject.setURI (sFilename);
    dataObject.setMimeType (aMimeType.getAsString ());
    dataObject.setDigestValue (internalGetMessageDigest ().digest ());

    final DigestMethodType digestMethodType = new DigestMethodType ();
    digestMethodType.setAlgorithm (getMessageDigestAlgorithm ().getUri ());
    dataObject.setDigestMethod (digestMethodType);

    m_aManifest.getDataObjectReference ().add (dataObject);
    if (LOG.isDebugEnabled ())
      LOG.debug ("Digest: " + Base64.encodeBytes (dataObject.getDigestValue ()));
  }

  /**
   * Locates the DataObjectReference for the given file name and sets the
   * attribute Rootfile to Boolean.TRUE
   *
   * @param entryName
   *        name of entry for which the attribute <code>Rootfile</code> should
   *        be set to "true".
   */
  public void setRootfileForEntry (final String entryName)
  {
    if (m_bRootFilenameIsSet)
      throw new IllegalStateException ("Multiple root files are not allowed.");

    for (final DataObjectReferenceType dataObject : m_aManifest.getDataObjectReference ())
    {
      if (dataObject.getURI ().equals (entryName))
      {
        dataObject.setRootfile (Boolean.TRUE);
        m_bRootFilenameIsSet = true;
        return;
      }
    }
  }

  public void setSignature (final String sFilename, final String sMimeType)
  {
    final SigReferenceType sigReferenceType = new SigReferenceType ();
    sigReferenceType.setURI (sFilename);
    sigReferenceType.setMimeType (sMimeType);
    m_aManifest.setSigReference (sigReferenceType);
  }

  @Nonnull
  public ASiCManifestType getASiCManifest ()
  {
    return m_aManifest;
  }

  @Nullable
  public byte [] getAsBytes ()
  {
    return AsicWriter.asicManifest ().getAsBytes (m_aManifest);
  }

  public static String extractAndVerify (final String sXml, final ManifestVerifier aMV)
  {
    // Updating namespaces for compatibility with previous releases and other
    // implementations
    String xml = sXml.replace ("http://uri.etsi.org/02918/v1.1.1#", "http://uri.etsi.org/02918/v1.2.1#");
    xml = xml.replace ("http://uri.etsi.org/2918/v1.2.1#", "http://uri.etsi.org/02918/v1.2.1#");
    xml = xml.replaceAll ("http://www.w3.org/2000/09/xmldsig#sha", "http://www.w3.org/2001/04/xmlenc#sha");

    // Read XML
    final ASiCManifestType manifest = AsicReader.asicManifest ().read (xml);
    if (manifest == null)
      throw new IllegalStateException ("Unable to read content as XML");

    String sigReference = manifest.getSigReference ().getURI ();
    if (sigReference == null)
      sigReference = "META-INF/signature.p7s";

    // Run through recorded objects
    for (final DataObjectReferenceType aDOR : manifest.getDataObjectReference ())
    {
      aMV.update (aDOR.getURI (),
                               aDOR.getMimeType (),
                               aDOR.getDigestValue (),
                               aDOR.getDigestMethod ().getAlgorithm (),
                               sigReference);
      if (aDOR.isRootfile () == Boolean.TRUE)
        aMV.setRootFilename (aDOR.getURI ());
    }

    return sigReference;
  }
}
