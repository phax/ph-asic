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

import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.base64.Base64;

/**
 * @author steinar Date: 03.07.15 Time: 14.47
 */
public class SignatureTest
{
  private static final Logger log = LoggerFactory.getLogger (SignatureTest.class);

  @Test
  public void createSampleDigest () throws Exception
  {
    try (final InputStream is = SignatureTest.class.getClassLoader ()
                                                   .getResourceAsStream (TestUtil.BII_SAMPLE_MESSAGE_XML))
    {
      assertNotNull (is);

      final MessageDigest md = MessageDigest.getInstance ("SHA-256");
      final ByteArrayOutputStream baos = new ByteArrayOutputStream ();
      try (final DigestOutputStream outputStream = new DigestOutputStream (baos, md))
      {
        int c;
        while ((c = is.read ()) > -1)
        {
          outputStream.write (c);
        }
      }

      final byte [] digest = md.digest ();
      final byte [] bytes = Base64.encodeBytesToBytes (digest);
      log.debug (new String (bytes));
    }
  }

  /**
   * Will not work with Java 1.8
   *
   * @throws Exception
   *//*
      * @Test public void createSignature() throws Exception { char[] password =
      * "123".toCharArray(); String text = "text"; CertAndKeyGen certAndKeyGen =
      * new CertAndKeyGen("RSA", "SHA1WithRSA", null); X500Name x500Name = new
      * X500Name("Cook", "ICT", "Balder Programvare", "Fjellhamar", "Akershus",
      * "Norway"); certAndKeyGen.generate(1024); PrivateKey pKey =
      * certAndKeyGen.getPrivateKey(); X509Certificate c =
      * certAndKeyGen.getSelfCertificate(x500Name, new Date(), 42); //Data to
      * sign byte[] dataToSign = text.getBytes("UTF-8"); //compute signature:
      * Signature signature = Signature.getInstance("SHA1WithRSA");
      * signature.initSign(pKey); signature.update(dataToSign); byte[]
      * signedData = signature.sign(); //load X500Name X500Name xName =
      * X500Name.asX500Name(c.getSubjectX500Principal()); //load serial number
      * BigInteger serial = c.getSerialNumber(); //laod digest algorithm
      * AlgorithmId digestAlgorithmId = new AlgorithmId(AlgorithmId.SHA_oid);
      * //load signing algorithm AlgorithmId signAlgorithmId = new
      * AlgorithmId(AlgorithmId.RSAEncryption_oid); //Create SignerInfo:
      * SignerInfo sInfo = new SignerInfo(xName, serial, digestAlgorithmId,
      * signAlgorithmId, signedData); //Create ContentInfo: ContentInfo cInfo =
      * new ContentInfo(ContentInfo.DATA_OID, new
      * DerValue(DerValue.tag_OctetString, dataToSign)); //Create PKCS7 Signed
      * data PKCS7 p7 = new PKCS7(new AlgorithmId[] { digestAlgorithmId },
      * cInfo, new java.security.cert.X509Certificate[] {
      */
  /* cert, *//*
              * }, new SignerInfo[] { sInfo }); //Write PKCS7 to bYteArray
              * ByteArrayOutputStream bOut = new DerOutputStream();
              * p7.encodeSignedData(bOut); byte[] encoded = bOut.toByteArray();
              * byte[] bytes = Base64.encodeBase64(encoded);
              * System.out.println(p7.toString()); }
              */

}
