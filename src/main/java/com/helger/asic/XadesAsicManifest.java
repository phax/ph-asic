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
package com.helger.asic;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.jspecify.annotations.NonNull;

import com.helger.asic.jaxb.cades.XAdESSignaturesType;
import com.helger.base.io.nonblocking.NonBlockingByteArrayOutputStream;
import com.helger.datetime.helper.PDTFactory;
import com.helger.jaxb.JAXBContextCache;
import com.helger.jaxb.JAXBContextCacheKey;
import com.helger.jaxb.JAXBMarshallerHelper;
import com.helger.mime.IMimeType;
import com.helger.xml.namespace.MapBasedNamespaceContext;
import com.helger.xml.transform.TransformSourceFactory;
import com.helger.xsds.xades132.CXAdES132;
import com.helger.xsds.xades132.CertIDListType;
import com.helger.xsds.xades132.CertIDType;
import com.helger.xsds.xades132.DataObjectFormatType;
import com.helger.xsds.xades132.DigestAlgAndValueType;
import com.helger.xsds.xades132.QualifyingPropertiesType;
import com.helger.xsds.xades132.SignedDataObjectPropertiesType;
import com.helger.xsds.xades132.SignedPropertiesType;
import com.helger.xsds.xades132.SignedSignaturePropertiesType;
import com.helger.xsds.xmldsig.CXMLDSig;
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

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;

public class XadesAsicManifest extends AbstractAsicManifest
{
  // Thread safe
  private static final JAXBContext JAXB_CONTEXT;
  private static final com.helger.xsds.xades132.ObjectFactory OF_XADES = new com.helger.xsds.xades132.ObjectFactory ();
  private static final com.helger.asic.jaxb.cades.ObjectFactory OF_CADES = new com.helger.asic.jaxb.cades.ObjectFactory ();
  private static final com.helger.xsds.xmldsig.ObjectFactory OF_XMLDSIG = new com.helger.xsds.xmldsig.ObjectFactory ();

  static
  {
    try
    {
      JAXB_CONTEXT = false ? JAXBContextCache.getInstance ()
                                             .getFromCache (JAXBContextCacheKey.createForClass (XAdESSignaturesType.class))
                           : JAXBContext.newInstance (XAdESSignaturesType.class,
                                                      X509DataType.class,
                                                      QualifyingPropertiesType.class);
    }
    catch (final JAXBException e)
    {
      throw new IllegalStateException ("Unable to create JAXBContext: " + e.getMessage (), e);
    }
  }

  // \XAdESSignature\Signature\SignedInfo
  private final SignedInfoType m_aSignedInfo;
  // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedDataObjectProperties
  private final SignedDataObjectPropertiesType m_aSignedDataObjectProperties = new SignedDataObjectPropertiesType ();

  public XadesAsicManifest (@NonNull final EMessageDigestAlgorithm eMDAlgo)
  {
    super (eMDAlgo);

    // \XAdESSignature\Signature\SignedInfo
    m_aSignedInfo = new SignedInfoType ();

    // \XAdESSignature\Signature\SignedInfo\CanonicalizationMethod
    final CanonicalizationMethodType canonicalizationMethod = new CanonicalizationMethodType ();
    canonicalizationMethod.setAlgorithm ("http://www.w3.org/2006/12/xml-c14n11");
    m_aSignedInfo.setCanonicalizationMethod (canonicalizationMethod);

    // \XAdESSignature\Signature\SignedInfo\SignatureMethod
    final SignatureMethodType signatureMethod = new SignatureMethodType ();
    signatureMethod.setAlgorithm (eMDAlgo.getUri ());
    m_aSignedInfo.setSignatureMethod (signatureMethod);
  }

  @Override
  public void add (final String sFilename, @NonNull final IMimeType aMimeType)
  {
    final String id = "ID_" + m_aSignedInfo.getReference ().size ();

    {
      // \XAdESSignature\Signature\SignedInfo\Reference
      final ReferenceType reference = new ReferenceType ();
      reference.setId (id);
      reference.setURI (sFilename);
      reference.setDigestValue (internalGetMessageDigest ().digest ());

      // \XAdESSignature\Signature\SignedInfo\Reference\DigestMethod
      final DigestMethodType digestMethodType = new DigestMethodType ();
      digestMethodType.setAlgorithm (getMessageDigestAlgorithm ().getUri ());
      reference.setDigestMethod (digestMethodType);

      m_aSignedInfo.getReference ().add (reference);
    }

    {
      // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedDataObjectProperties\DataObjectFormat
      final DataObjectFormatType dataObjectFormatType = new DataObjectFormatType ();
      dataObjectFormatType.setObjectReference ("#" + id);
      dataObjectFormatType.setMimeType (aMimeType.getAsString ());

      m_aSignedDataObjectProperties.getDataObjectFormat ().add (dataObjectFormatType);
    }
  }

  @NonNull
  XAdESSignaturesType getCreateXAdESSignatures (@NonNull final SignatureHelper aSH)
  {
    // \XAdESSignature
    final XAdESSignaturesType xAdESSignaturesType = new XAdESSignaturesType ();

    // \XAdESSignature\Signature
    final SignatureType aSignature = new SignatureType ();
    aSignature.setId ("Signature");
    aSignature.setSignedInfo (m_aSignedInfo);
    xAdESSignaturesType.addSignature (aSignature);

    // \XAdESSignature\Signature\KeyInfo
    final KeyInfoType aKeyInfo = new KeyInfoType ();
    aKeyInfo.addContent (_getX509Data (aSH));
    aSignature.setKeyInfo (aKeyInfo);

    // \XAdESSignature\Signature\Object
    final ObjectType aObject = new ObjectType ();
    aObject.addContent (_getQualifyingProperties (aSH));
    aSignature.addObject (aObject);

    // \XAdESSignature\Signature\Object\SignatureValue
    aSignature.setSignatureValue (getSignature ());

    return xAdESSignaturesType;
  }

  public byte [] getAsBytes (@NonNull final SignatureHelper aSH)
  {
    try
    {
      final Marshaller aMarshaller = JAXB_CONTEXT.createMarshaller ();
      JAXBMarshallerHelper.setFormattedOutput (aMarshaller, true);
      final MapBasedNamespaceContext aNSCtx = new MapBasedNamespaceContext ();
      aNSCtx.addMapping (CXMLDSig.DEFAULT_PREFIX, CXMLDSig.NAMESPACE_URI);
      aNSCtx.addMapping (CXAdES132.DEFAULT_PREFIX, CXAdES132.NAMESPACE_URI);
      JAXBMarshallerHelper.setJakartaNamespacePrefixMapper (aMarshaller, aNSCtx);

      try (final NonBlockingByteArrayOutputStream aBAOS = new NonBlockingByteArrayOutputStream ())
      {
        // TODO
        aMarshaller.marshal (OF_CADES.createXAdESSignatures (getCreateXAdESSignatures (aSH)), aBAOS);
        return aBAOS.toByteArray ();
      }
    }
    catch (final JAXBException ex)
    {
      throw new IllegalStateException ("Unable to marshall the XAdESSignature into string output", ex);
    }
  }

  @NonNull
  private JAXBElement <X509DataType> _getX509Data (@NonNull final SignatureHelper aSH)
  {
    // \XAdESSignature\Signature\KeyInfo\X509Data
    final X509DataType x509DataType = new X509DataType ();

    for (final Certificate aCert : aSH.getCertificateChain ())
    {
      try
      {
        // \XAdESSignature\Signature\KeyInfo\X509Data\X509Certificate
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName ()
                    .add (OF_XMLDSIG.createX509DataTypeX509Certificate (aCert.getEncoded ()));
      }
      catch (final CertificateEncodingException e)
      {
        throw new IllegalStateException ("Unable to insert certificate.", e);
      }
    }

    return OF_XMLDSIG.createX509Data (x509DataType);
  }

  private JAXBElement <QualifyingPropertiesType> _getQualifyingProperties (@NonNull final SignatureHelper aSH)
  {
    // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedSignatureProperties
    final SignedSignaturePropertiesType aSignedSignatureProperties = new SignedSignaturePropertiesType ();

    // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedSignatureProperties\SigningTime
    aSignedSignatureProperties.setSigningTime (PDTFactory.getCurrentXMLOffsetDateTime ());

    // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedSignatureProperties\SigningCertificate
    final CertIDListType aCertIDList = new CertIDListType ();
    aSignedSignatureProperties.setSigningCertificate (aCertIDList);

    // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedSignatureProperties\SigningCertificate\Cert
    final CertIDType aCertID = new CertIDType ();
    aCertIDList.addCert (aCertID);

    try
    {
      // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedSignatureProperties\SigningCertificate\Cert\CertDigest
      final DigestAlgAndValueType aCertDigest = new DigestAlgAndValueType ();
      final MessageDigest aMD = MessageDigest.getInstance (getMessageDigestAlgorithm ().getMessageDigestAlgorithm ());
      aCertDigest.setDigestValue (aMD.digest (aSH.getX509Certificate ().getEncoded ()));
      aCertID.setCertDigest (aCertDigest);

      // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedSignatureProperties\SigningCertificate\Cert\CertDigest\DigestMethod
      final DigestMethodType aDigestMethod = new DigestMethodType ();
      aDigestMethod.setAlgorithm (getMessageDigestAlgorithm ().getUri ());
      aCertDigest.setDigestMethod (aDigestMethod);
    }
    catch (final CertificateEncodingException e)
    {
      throw new IllegalStateException ("Unable to encode certificate.", e);
    }
    catch (final NoSuchAlgorithmException ex)
    {
      throw new IllegalStateException ("Message Digest Algorithm '" +
                                       getMessageDigestAlgorithm ().getMessageDigestAlgorithm () +
                                       "' is not supported",
                                       ex);
    }

    // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties\SignedSignatureProperties\SigningCertificate\Cert\IssuerSerial
    final X509IssuerSerialType aX509IssuerSerial = new X509IssuerSerialType ();
    aX509IssuerSerial.setX509IssuerName (aSH.getX509Certificate ().getIssuerX500Principal ().getName ());
    aX509IssuerSerial.setX509SerialNumber (aSH.getX509Certificate ().getSerialNumber ());
    aCertID.setIssuerSerial (aX509IssuerSerial);

    // \XAdESSignature\Signature\Object\QualifyingProperties\SignedProperties
    final SignedPropertiesType aSignedProperties = new SignedPropertiesType ();
    aSignedProperties.setId ("SignedProperties");
    aSignedProperties.setSignedSignatureProperties (aSignedSignatureProperties);
    aSignedProperties.setSignedDataObjectProperties (m_aSignedDataObjectProperties);

    // \XAdESSignature\Signature\Object\QualifyingProperties
    final QualifyingPropertiesType aQualifyingProperties = new QualifyingPropertiesType ();
    // qualifyingPropertiesType.setSignedProperties(signedPropertiesType);
    aQualifyingProperties.setTarget ("#Signature");

    // Adding digest of SignedProperties into SignedInfo
    {
      // \XAdESSignature\Signature\SignedInfo\Reference
      final ReferenceType aReference = new ReferenceType ();
      aReference.setType ("http://uri.etsi.org/01903#SignedProperties");
      aReference.setURI ("#SignedProperties");
      // TODO Generate digest

      // \XAdESSignature\Signature\SignedInfo\Reference\Transforms
      final TransformsType aTransforms = new TransformsType ();
      aReference.setTransforms (aTransforms);

      // \XAdESSignature\Signature\SignedInfo\Reference\Transforms\Transform
      final TransformType aTransform = new TransformType ();
      aTransform.setAlgorithm (CanonicalizationMethod.INCLUSIVE);
      aReference.getTransforms ().addTransform (aTransform);

      // \XAdESSignature\Signature\SignedInfo\Reference\DigestMethod
      final DigestMethodType aDigestMethod = new DigestMethodType ();
      aDigestMethod.setAlgorithm (getMessageDigestAlgorithm ().getUri ());
      aReference.setDigestMethod (aDigestMethod);

      m_aSignedInfo.addReference (aReference);
    }

    return OF_XADES.createQualifyingProperties (aQualifyingProperties);
  }

  protected SignatureValueType getSignature ()
  {
    // TODO Generate signature
    // http://stackoverflow.com/questions/30596933/xades-bes-detached-signedproperties-reference-wrong-digestvalue-java

    // final DigestMethod dm = fac.newDigestMethod (DigestMethod.SHA1, null);
    // final CanonicalizationMethod cn = fac.newCanonicalizationMethod
    // (CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
    // (C14NMethodParameterSpec) null);
    // final List <Reference> refs = new ArrayList <> ();
    // final Reference ref1 = fac.newReference (pathName, dm, null, null,
    // signedRefID, messageDigest2.digest (datax));
    // refs.add (ref1);
    // final Canonicalizer cn14 = Canonicalizer.getInstance
    // (Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
    // byte [] canon;
    // canon = cn14.canonicalizeSubtree (SPElement);
    // final Reference ref2 = fac.newReference ("#" + signedPropID,
    // dm,
    // null,
    // sigProp,
    // signedPropRefID,
    // messageDigest2.digest (canon));
    // refs.add (ref2);
    // final SignatureMethod sm = fac.newSignatureMethod
    // (SignatureMethod.RSA_SHA1, null);
    // final SignedInfo si = fac.newSignedInfo (cn, sm, refs);
    // final XMLSignature signature = fac.newXMLSignature (si, ki, objects,
    // signatureID, null);
    // signature.sign (dsc);

    return new SignatureValueType ();
  }

  public static void extractAndVerify (@NonNull final String sXml, final ManifestVerifier aMV)
  {
    // Updating namespace
    String sRealXML = sXml.replace ("http://uri.etsi.org/02918/v1.1.1#", "http://uri.etsi.org/02918/v1.2.1#");
    sRealXML = sRealXML.replace ("http://uri.etsi.org/2918/v1.2.1#", "http://uri.etsi.org/02918/v1.2.1#");
    sRealXML = sRealXML.replace ("http://www.w3.org/2000/09/xmldsig#sha", "http://www.w3.org/2001/04/xmlenc#sha");

    XAdESSignaturesType aXadesSignatures;

    try
    {
      final Unmarshaller aUnmarshaller = JAXB_CONTEXT.createUnmarshaller ();
      aXadesSignatures = aUnmarshaller.unmarshal (TransformSourceFactory.create (sRealXML), XAdESSignaturesType.class)
                                      .getValue ();
    }
    catch (final Exception ex)
    {
      throw new IllegalStateException ("Unable to read content as XML", ex);
    }

    for (final SignatureType aSignature : aXadesSignatures.getSignature ())
    {
      // SignedInfo is mandatory
      final SignedInfoType aSignedInfo = aSignature.getSignedInfo ();
      for (final ReferenceType aRef : aSignedInfo.getReference ())
      {
        // URI is optional
        if (aRef.getURI () != null && !aRef.getURI ().startsWith ("#"))
        {
          // DigestMethod is mandatory
          aMV.update (aRef.getURI (), null, aRef.getDigestValue (), aRef.getDigestMethod ().getAlgorithm (), null);
        }
      }
    }
  }
}
