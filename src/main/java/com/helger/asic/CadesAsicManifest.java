package com.helger.asic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.asic.jaxb.cades.ASiCManifestType;
import com.helger.asic.jaxb.cades.DataObjectReferenceType;
import com.helger.asic.jaxb.cades.ObjectFactory;
import com.helger.asic.jaxb.cades.SigReferenceType;
import com.helger.xsds.xmldsig.DigestMethodType;

public class CadesAsicManifest extends AbstractAsicManifest
{
  private static final Logger logger = LoggerFactory.getLogger (AbstractAsicManifest.class);

  private static JAXBContext jaxbContext; // Thread safe
  private static ObjectFactory objectFactory = new ObjectFactory ();

  static
  {
    try
    {
      jaxbContext = JAXBContext.newInstance (ASiCManifestType.class);
    }
    catch (final JAXBException e)
    {
      throw new IllegalStateException (String.format ("Unable to create JAXBContext: %s ", e.getMessage ()), e);
    }
  }

  // Automagically generated from XML Schema Definition files
  private final ASiCManifestType ASiCManifestType = new ASiCManifestType ();
  private boolean rootFilenameIsSet = false;

  public CadesAsicManifest (final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    super (messageDigestAlgorithm);
  }

  @Override
  public void add (final String filename, final MimeType mimeType)
  {
    final DataObjectReferenceType dataObject = new DataObjectReferenceType ();
    dataObject.setURI (filename);
    dataObject.setMimeType (mimeType.toString ());
    dataObject.setDigestValue (m_aMD.digest ());

    final DigestMethodType digestMethodType = new DigestMethodType ();
    digestMethodType.setAlgorithm (m_aMessageDigestAlgorithm.getUri ());
    dataObject.setDigestMethod (digestMethodType);

    ASiCManifestType.getDataObjectReference ().add (dataObject);
    logger.debug ("Digest: {}", Base64.encode (dataObject.getDigestValue ()));
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
    if (rootFilenameIsSet)
      throw new IllegalStateException ("Multiple root files are not allowed.");

    for (final DataObjectReferenceType dataObject : ASiCManifestType.getDataObjectReference ())
    {
      if (dataObject.getURI ().equals (entryName))
      {
        dataObject.setRootfile (Boolean.TRUE);
        rootFilenameIsSet = true;
        return;
      }
    }
  }

  public void setSignature (final String filename, final String mimeType)
  {
    final SigReferenceType sigReferenceType = new SigReferenceType ();
    sigReferenceType.setURI (filename);
    sigReferenceType.setMimeType (mimeType);
    ASiCManifestType.setSigReference (sigReferenceType);
  }

  public ASiCManifestType getASiCManifestType ()
  {
    return ASiCManifestType;
  }

  public byte [] toBytes ()
  {
    try
    {
      final Marshaller marshaller = jaxbContext.createMarshaller ();
      marshaller.setProperty (Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

      final ByteArrayOutputStream baos = new ByteArrayOutputStream ();
      marshaller.marshal (objectFactory.createASiCManifest (ASiCManifestType), baos);
      return baos.toByteArray ();
    }
    catch (final JAXBException e)
    {
      throw new IllegalStateException ("Unable to marshall the ASiCManifest into string output", e);
    }
  }

  public static String extractAndVerify (final String sXml, final ManifestVerifier manifestVerifier)
  {
    // Updating namespaces for compatibility with previous releases and other
    // implementations
    String xml = sXml.replace ("http://uri.etsi.org/02918/v1.1.1#", "http://uri.etsi.org/02918/v1.2.1#");
    xml = xml.replace ("http://uri.etsi.org/2918/v1.2.1#", "http://uri.etsi.org/02918/v1.2.1#");
    xml = xml.replaceAll ("http://www.w3.org/2000/09/xmldsig#sha", "http://www.w3.org/2001/04/xmlenc#sha");

    try
    {
      // Read XML
      final Unmarshaller unmarshaller = jaxbContext.createUnmarshaller ();
      final ASiCManifestType manifest = ((JAXBElement <ASiCManifestType>) unmarshaller.unmarshal (new ByteArrayInputStream (xml.getBytes ()))).getValue ();

      String sigReference = manifest.getSigReference ().getURI ();
      if (sigReference == null)
        sigReference = "META-INF/signature.p7s";

      // Run through recorded objects
      for (final DataObjectReferenceType reference : manifest.getDataObjectReference ())
      {
        manifestVerifier.update (reference.getURI (),
                                 reference.getMimeType (),
                                 reference.getDigestValue (),
                                 reference.getDigestMethod ().getAlgorithm (),
                                 sigReference);
        if (reference.isRootfile () == Boolean.TRUE)
          manifestVerifier.setRootFilename (reference.getURI ());
      }

      return sigReference;
    }
    catch (final JAXBException e)
    {
      throw new IllegalStateException ("Unable to read content as XML", e);
    }
  }

}
