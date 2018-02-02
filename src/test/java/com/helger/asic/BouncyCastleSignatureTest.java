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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.base64.Base64;

/**
 * @author steinar Date: 05.07.15 Time: 21.57
 */
public class BouncyCastleSignatureTest
{
  private KeyPair keyPair;
  private X509Certificate x509Certificate;

  public static final Logger log = LoggerFactory.getLogger (BouncyCastleSignatureTest.class);

  @Before
  public void setUp ()
  {
    Security.addProvider (new BouncyCastleProvider ());
  }

  @Test
  public void createSignature () throws Exception
  {

    final CMSProcessableByteArray msg = new CMSProcessableByteArray ("Hello world".getBytes (StandardCharsets.ISO_8859_1));
    // generateKeyPairAndCertificate();
    // Reads private key and certificate from our own
    // keystore
    keyPair = getKeyPair ();

    final String keyAlgorithm = keyPair.getPrivate ().getAlgorithm ();

    final List <?> certList = new ArrayList <> ();
    final JcaCertStore jcaCertStore = new JcaCertStore (certList);
    final CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator ();
    final String signatureAlgorithm = "SHA1with" + keyAlgorithm;
    final ContentSigner sha1Signer = new JcaContentSignerBuilder (signatureAlgorithm).setProvider (BouncyCastleProvider.PROVIDER_NAME)
                                                                                     .build (keyPair.getPrivate ());

    final DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder ().setProvider (BouncyCastleProvider.PROVIDER_NAME)
                                                                                                       .build ();
    final SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder (digestCalculatorProvider).build (sha1Signer,
                                                                                                                        x509Certificate);
    cmsSignedDataGenerator.addSignerInfoGenerator (signerInfoGenerator);
    cmsSignedDataGenerator.addCertificates (jcaCertStore);
    final CMSSignedData sigData = cmsSignedDataGenerator.generate (msg, false);

    log.info (Base64.encodeBytes (sigData.getEncoded ()));
  }

  void generateKeyPairAndCertificate () throws NoSuchProviderException,
                                        NoSuchAlgorithmException,
                                        OperatorCreationException,
                                        CertificateException,
                                        SignatureException,
                                        InvalidKeyException
  {

    final String BC = BouncyCastleProvider.PROVIDER_NAME;
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance ("DSA", BC);
    keyPairGenerator.initialize (1024, new SecureRandom ());
    keyPair = keyPairGenerator.generateKeyPair ();

    final X500NameBuilder nameBuilder = createStdBuilder ();

    final ContentSigner sigGen = new JcaContentSignerBuilder ("SHA1withDSA").setProvider (BC)
                                                                            .build (keyPair.getPrivate ());
    final JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder (nameBuilder.build (),
                                                                                 BigInteger.valueOf (1),
                                                                                 new Date (System.currentTimeMillis () -
                                                                                           50000),
                                                                                 new Date (System.currentTimeMillis () +
                                                                                           50000),
                                                                                 nameBuilder.build (),
                                                                                 keyPair.getPublic ());

    x509Certificate = new JcaX509CertificateConverter ().setProvider (BC).getCertificate (certGen.build (sigGen));

    x509Certificate.checkValidity (new Date ());

    x509Certificate.verify (keyPair.getPublic ());

    final ByteArrayInputStream bIn = new ByteArrayInputStream (x509Certificate.getEncoded ());
    final CertificateFactory fact = CertificateFactory.getInstance ("X.509", BC);

    x509Certificate = (X509Certificate) fact.generateCertificate (bIn);

    System.out.println (x509Certificate);
  }

  private X500NameBuilder createStdBuilder ()
  {
    final X500NameBuilder builder = new X500NameBuilder (BCStyle.INSTANCE);

    builder.addRDN (BCStyle.C, "AU");
    builder.addRDN (BCStyle.O, "The Legion of the Bouncy Castle");
    builder.addRDN (BCStyle.L, "Melbourne");
    builder.addRDN (BCStyle.ST, "Victoria");
    builder.addRDN (BCStyle.E, "feedback-crypto@bouncycastle.org");

    return builder;
  }

  KeyPair getKeyPair () throws KeyStoreException,
                        CertificateException,
                        NoSuchAlgorithmException,
                        IOException,
                        UnrecoverableKeyException
  {
    final KeyStore keyStore = KeyStore.getInstance ("JKS");

    final FileInputStream fileInputStream = new FileInputStream (new File ("src/test/resources/keystore.jks"));

    keyStore.load (fileInputStream, "changeit".toCharArray ());

    final String alias = keyStore.aliases ().nextElement ();
    final X509Certificate certificate = (X509Certificate) keyStore.getCertificate (alias);

    x509Certificate = certificate;

    final Key key = keyStore.getKey (alias, "changeit".toCharArray ());
    final PrivateKey privateKey = (PrivateKey) key;

    return new KeyPair (certificate.getPublicKey (), privateKey);
  }

}
