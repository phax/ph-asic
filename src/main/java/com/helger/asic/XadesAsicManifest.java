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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;

import com.helger.asic.jaxb.cades.XAdESSignaturesType;
import com.helger.commons.mime.IMimeType;
import com.helger.datetime.util.PDTXMLConverter;
import com.helger.xsds.xades132.CertIDListType;
import com.helger.xsds.xades132.CertIDType;
import com.helger.xsds.xades132.DataObjectFormatType;
import com.helger.xsds.xades132.DigestAlgAndValueType;
import com.helger.xsds.xades132.QualifyingPropertiesType;
import com.helger.xsds.xades132.SignedDataObjectPropertiesType;
import com.helger.xsds.xades132.SignedPropertiesType;
import com.helger.xsds.xades132.SignedSignaturePropertiesType;
import com.helger.xsds.xmldsig.CanonicalizationMethodType;
import com.helger.xsds.xmldsig.DigestMethodType;
import com.helger.xsds.xmldsig.KeyInfoType;
import com.helger.xsds.xmldsig.ObjectType;
import com.helger.xsds.xmldsig.ReferenceType;
import com.helger.xsds.xmldsig.SignatureMethodType;
import com.helger.xsds.xmldsig.SignatureType;
import com.helger.xsds.xmldsig.SignatureValueType;
import com.helger.xsds.xmldsig.SignedInfoType;
import com.helger.xsds.xmldsig.TransformType;
import com.helger.xsds.xmldsig.TransformsType;
import com.helger.xsds.xmldsig.X509DataType;
import com.helger.xsds.xmldsig.X509IssuerSerialType;

public class XadesAsicManifest extends AbstractAsicManifest
{
  private static JAXBContext jaxbContext; // Thread safe
  private static com.helger.xsds.xades132.ObjectFactory objectFactory1_2 = new com.helger.xsds.xades132.ObjectFactory ();
  private static com.helger.asic.jaxb.cades.ObjectFactory objectFactory1_3 = new com.helger.asic.jaxb.cades.ObjectFactory ();

  static
  {
    try
    {
      jaxbContext = JAXBContext.newInstance (XAdESSignaturesType.class,
                                             X509DataType.class,
                                             QualifyingPropertiesType.class);
    }
    catch (final JAXBException e)
    {
      throw new IllegalStateException ("Unable to create JAXBContext: " + e.getMessage (), e);
    }
  }

  // \XAdESSignature\Signature\SignedInfo
  private final SignedInfoType signedInfo;
  // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedDataObjectProperties
  private final SignedDataObjectPropertiesType signedDataObjectProperties = new SignedDataObjectPropertiesType ();

  public XadesAsicManifest (final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    super (messageDigestAlgorithm);

    // \XAdESSignature\Signature\SignedInfo
    signedInfo = new SignedInfoType ();

    // \XAdESSignature\Signature\SignedInfo\CanonicalizationMethod
    final CanonicalizationMethodType canonicalizationMethod = new CanonicalizationMethodType ();
    canonicalizationMethod.setAlgorithm ("http://www.w3.org/2006/12/xml-c14n11");
    signedInfo.setCanonicalizationMethod (canonicalizationMethod);

    // \XAdESSignature\Signature\SignedInfo\SignatureMethod
    final SignatureMethodType signatureMethod = new SignatureMethodType ();
    signatureMethod.setAlgorithm (messageDigestAlgorithm.getUri ());
    signedInfo.setSignatureMethod (signatureMethod);
  }

  @Override
  public void add (final String filename, final IMimeType aMimeType)
  {
    final String id = "ID_" + signedInfo.getReference ().size ();

    {
      // \XAdESSignature\Signature\SignedInfo\Reference
      final ReferenceType reference = new ReferenceType ();
      reference.setId (id);
      reference.setURI (filename);
      reference.setDigestValue (internalGetMessageDigest ().digest ());

      // \XAdESSignature\Signature\SignedInfo\Reference\DigestMethod
      final DigestMethodType digestMethodType = new DigestMethodType ();
      digestMethodType.setAlgorithm (getMessageDigestAlgorithm ().getUri ());
      reference.setDigestMethod (digestMethodType);

      signedInfo.getReference ().add (reference);
    }

    {
      // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedDataObjectProperties\DataObjectFormat
      final DataObjectFormatType dataObjectFormatType = new DataObjectFormatType ();
      dataObjectFormatType.setObjectReference ("#" + id);
      dataObjectFormatType.setMimeType (aMimeType.getAsString ());

      signedDataObjectProperties.getDataObjectFormat ().add (dataObjectFormatType);
    }
  }

  XAdESSignaturesType getCreateXAdESSignatures (final SignatureHelper signatureHelper)
  {
    // \XAdESSignature
    final XAdESSignaturesType xAdESSignaturesType = new XAdESSignaturesType ();

    // \XAdESSignature\Signature
    final SignatureType signatureType = new SignatureType ();
    signatureType.setId ("Signature");
    signatureType.setSignedInfo (signedInfo);
    xAdESSignaturesType.getSignature ().add (signatureType);

    // \XAdESSignature\Signature\KeyInfo
    final KeyInfoType keyInfoType = new KeyInfoType ();
    keyInfoType.getContent ().add (_getX509Data (signatureHelper));
    signatureType.setKeyInfo (keyInfoType);

    // \XAdESSignature\Signature\Object
    final ObjectType objectType = new ObjectType ();
    objectType.getContent ().add (_getQualifyingProperties (signatureHelper));
    signatureType.getObject ().add (objectType);

    // \XAdESSignature\Signature\Object\SignatureValue
    signatureType.setSignatureValue (getSignature ());

    return xAdESSignaturesType;
  }

  public byte [] toBytes (final SignatureHelper signatureHelper)
  {
    try
    {
      final Marshaller marshaller = jaxbContext.createMarshaller ();
      marshaller.setProperty (Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

      final ByteArrayOutputStream baos = new ByteArrayOutputStream ();
      // TODO
      marshaller.marshal (objectFactory1_3.createXAdESSignatures (getCreateXAdESSignatures (signatureHelper)), baos);
      return baos.toByteArray ();
    }
    catch (final JAXBException e)
    {
      throw new IllegalStateException ("Unable to marshall the XAdESSignature into string output", e);
    }
  }

  private JAXBElement <X509DataType> _getX509Data (final SignatureHelper signatureHelper)
  {
    final com.helger.xsds.xmldsig.ObjectFactory objectFactory = new com.helger.xsds.xmldsig.ObjectFactory ();

    // \XAdESSignature\Signature\KeyInfo\X509Data
    final X509DataType x509DataType = new X509DataType ();

    for (final Certificate certificate : signatureHelper.getCertificateChain ())
    {
      try
      {
        // \XAdESSignature\Signature\KeyInfo\X509Data\X509Certificate
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName ()
                    .add (objectFactory.createX509DataTypeX509Certificate (certificate.getEncoded ()));
      }
      catch (final CertificateEncodingException e)
      {
        throw new IllegalStateException ("Unable to insert certificate.", e);
      }
    }

    return objectFactory.createX509Data (x509DataType);
  }

  private JAXBElement <QualifyingPropertiesType> _getQualifyingProperties (final SignatureHelper signatureHelper)
  {
    // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedSignatureProperties
    final SignedSignaturePropertiesType signedSignaturePropertiesType = new SignedSignaturePropertiesType ();

    // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedSignatureProperties\SigningTime
    signedSignaturePropertiesType.setSigningTime (PDTXMLConverter.createNewCalendar ());

    // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedSignatureProperties\SigningCertificate
    final CertIDListType certIDListType = new CertIDListType ();
    signedSignaturePropertiesType.setSigningCertificate (certIDListType);

    // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedSignatureProperties\SigningCertificate\Cert
    final CertIDType cert = new CertIDType ();
    certIDListType.getCert ().add (cert);

    try
    {
      // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedSignatureProperties\SigningCertificate\Cert\CertDigest
      final DigestAlgAndValueType certDigest = new DigestAlgAndValueType ();
      certDigest.setDigestValue (com.helger.security.messagedigest.EMessageDigestAlgorithm.SHA_1.createMessageDigest ()
                                                                                                .digest (signatureHelper.getX509Certificate ()
                                                                                                                        .getEncoded ()));
      cert.setCertDigest (certDigest);

      // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedSignatureProperties\SigningCertificate\Cert\CertDigest\DigestMethod
      final DigestMethodType digestMethodType = new DigestMethodType ();
      digestMethodType.setAlgorithm ("http://www.w3.org/2000/09/xmldsig#sha1");
      certDigest.setDigestMethod (digestMethodType);
    }
    catch (final CertificateEncodingException e)
    {
      throw new IllegalStateException ("Unable to encode certificate.", e);
    }

    // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedSignatureProperties\SigningCertificate\Cert\IssuerSerial
    final X509IssuerSerialType issuerSerialType = new X509IssuerSerialType ();
    issuerSerialType.setX509IssuerName (signatureHelper.getX509Certificate ().getIssuerX500Principal ().getName ());
    issuerSerialType.setX509SerialNumber (signatureHelper.getX509Certificate ().getSerialNumber ());
    cert.setIssuerSerial (issuerSerialType);

    // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties
    final SignedPropertiesType signedPropertiesType = new SignedPropertiesType ();
    signedPropertiesType.setId ("SignedProperties");
    signedPropertiesType.setSignedSignatureProperties (signedSignaturePropertiesType);
    signedPropertiesType.setSignedDataObjectProperties (signedDataObjectProperties);

    // \XAdESSignature\Signature\Object\QualifyingProperties
    final QualifyingPropertiesType qualifyingPropertiesType = new QualifyingPropertiesType ();
    // qualifyingPropertiesType.setSignedProperties(signedPropertiesType);
    qualifyingPropertiesType.setTarget ("#Signature");

    // Adding digest of SignedProperties into SignedInfo
    {
      // \XAdESSignature\Signature\SignedInfo\Reference
      final ReferenceType reference = new ReferenceType ();
      reference.setType ("http://uri.etsi.org/01903#SignedProperties");
      reference.setURI ("#SignedProperties");
      // TODO Generate digest

      // \XAdESSignature\Signature\SignedInfo\Reference\Transforms
      final TransformsType transformsType = new TransformsType ();
      reference.setTransforms (transformsType);

      // \XAdESSignature\Signature\SignedInfo\Reference\Transforms\Transform
      final TransformType transformType = new TransformType ();
      transformType.setAlgorithm ("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
      reference.getTransforms ().getTransform ().add (transformType);

      // \XAdESSignature\Signature\SignedInfo\Reference\DigestMethod
      final DigestMethodType digestMethodType = new DigestMethodType ();
      digestMethodType.setAlgorithm (getMessageDigestAlgorithm ().getUri ());
      reference.setDigestMethod (digestMethodType);

      signedInfo.getReference ().add (reference);
    }

    return objectFactory1_2.createQualifyingProperties (qualifyingPropertiesType);
  }

  protected SignatureValueType getSignature ()
  {
    // TODO Generate signature
    // http://stackoverflow.com/questions/30596933/xades-bes-detached-signedproperties-reference-wrong-digestvalue-java

    /*
     * DigestMethod dm = fac.newDigestMethod(DigestMethod.SHA1, null);
     * CanonicalizationMethod cn =
     * fac.newCanonicalizationMethod(CanonicalizationMethod.
     * INCLUSIVE_WITH_COMMENTS,(C14NMethodParameterSpec) null); List<Reference>
     * refs = new ArrayList<Reference>(); Reference ref1 =
     * fac.newReference(pathName,
     * dm,null,null,signedRefID,messageDigest2.digest(datax)); refs.add(ref1);
     * Canonicalizer cn14 =
     * Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
     * byte[] canon; canon = cn14.canonicalizeSubtree(SPElement); Reference ref2
     * = fac.newReference("#"+signedPropID,dm, null , sigProp ,
     * signedPropRefID,messageDigest2.digest(canon)); refs.add(ref2);
     * SignatureMethod sm = fac.newSignatureMethod(SignatureMethod.RSA_SHA1,
     * null); SignedInfo si = fac.newSignedInfo(cn, sm, refs); XMLSignature
     * signature = fac.newXMLSignature(si, ki,objects,signatureID,null);
     * signature.sign(dsc);
     */

    return new SignatureValueType ();
  }

  public static void extractAndVerify (final String sXml, final ManifestVerifier manifestVerifier)
  {
    // Updating namespace
    String xml = sXml.replace ("http://uri.etsi.org/02918/v1.1.1#", "http://uri.etsi.org/02918/v1.2.1#");
    xml = xml.replace ("http://uri.etsi.org/2918/v1.2.1#", "http://uri.etsi.org/02918/v1.2.1#");
    xml = xml.replaceAll ("http://www.w3.org/2000/09/xmldsig#sha", "http://www.w3.org/2001/04/xmlenc#sha");

    XAdESSignaturesType manifest;

    try
    {
      final Unmarshaller unmarshaller = jaxbContext.createUnmarshaller ();
      manifest = unmarshaller.unmarshal (new StreamSource (new ByteArrayInputStream (xml.getBytes ())),
                                         XAdESSignaturesType.class)
                             .getValue ();
    }
    catch (final Exception e)
    {
      throw new IllegalStateException ("Unable to read content as XML", e);
    }

    for (final SignatureType signature : manifest.getSignature ())
    {
      final SignedInfoType signedInfoType = signature.getSignedInfo ();

      for (final ReferenceType reference : signedInfoType.getReference ())
      {
        if (!reference.getURI ().startsWith ("#"))
          manifestVerifier.update (reference.getURI (),
                                   null,
                                   reference.getDigestValue (),
                                   reference.getDigestMethod ().getAlgorithm (),
                                   null);
      }
    }
  }
}
