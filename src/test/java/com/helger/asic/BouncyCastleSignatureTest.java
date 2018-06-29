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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.annotation.Nonnull;

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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.bc.PBCProvider;
import com.helger.commons.base64.Base64;
import com.helger.commons.io.stream.NonBlockingByteArrayInputStream;

/**
 * @author steinar Date: 05.07.15 Time: 21.57
 */
public final class BouncyCastleSignatureTest
{
  private static final Logger log = LoggerFactory.getLogger (BouncyCastleSignatureTest.class);

  @Test
  public void createSignature () throws Exception
  {
    final CMSProcessableByteArray msg = new CMSProcessableByteArray ("Hello world".getBytes (StandardCharsets.ISO_8859_1));
    // generateKeyPairAndCertificate();
    // Reads private key and certificate from our own
    // keystore
    final SignatureHelper aSH = TestUtil.createSH ();
    final X509Certificate aX509Certificate = aSH.getX509Certificate ();
    final KeyPair aKeyPair = aSH.getKeyPair ();

    final String keyAlgorithm = aKeyPair.getPrivate ().getAlgorithm ();

    final List <?> certList = new ArrayList <> ();
    final JcaCertStore jcaCertStore = new JcaCertStore (certList);
    final CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator ();
    final String signatureAlgorithm = "SHA1with" + keyAlgorithm;
    final ContentSigner sha1Signer = new JcaContentSignerBuilder (signatureAlgorithm).setProvider (PBCProvider.getProvider ())
                                                                                     .build (aKeyPair.getPrivate ());

    final DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder ().setProvider (PBCProvider.getProvider ())
                                                                                                       .build ();
    final SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder (digestCalculatorProvider).build (sha1Signer,
                                                                                                                        aX509Certificate);
    cmsSignedDataGenerator.addSignerInfoGenerator (signerInfoGenerator);
    cmsSignedDataGenerator.addCertificates (jcaCertStore);
    final CMSSignedData sigData = cmsSignedDataGenerator.generate (msg, false);

    log.info (Base64.encodeBytes (sigData.getEncoded ()));
  }

  @Nonnull
  private static X500NameBuilder _createStdBuilder ()
  {
    final X500NameBuilder builder = new X500NameBuilder (BCStyle.INSTANCE);
    builder.addRDN (BCStyle.C, "AU");
    builder.addRDN (BCStyle.O, "The Legion of the Bouncy Castle");
    builder.addRDN (BCStyle.L, "Melbourne");
    builder.addRDN (BCStyle.ST, "Victoria");
    builder.addRDN (BCStyle.E, "feedback-crypto@bouncycastle.org");
    return builder;
  }

  void generateKeyPairAndCertificate () throws NoSuchProviderException,
                                        NoSuchAlgorithmException,
                                        OperatorCreationException,
                                        CertificateException,
                                        SignatureException,
                                        InvalidKeyException
  {
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance ("DSA", PBCProvider.getProvider ());
    keyPairGenerator.initialize (1024, new SecureRandom ());
    final KeyPair aKeyPair = keyPairGenerator.generateKeyPair ();

    final X500NameBuilder nameBuilder = _createStdBuilder ();

    final ContentSigner sigGen = new JcaContentSignerBuilder ("SHA1withDSA").setProvider (PBCProvider.getProvider ())
                                                                            .build (aKeyPair.getPrivate ());
    final JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder (nameBuilder.build (),
                                                                                 BigInteger.valueOf (1),
                                                                                 new Date (System.currentTimeMillis () -
                                                                                           50000),
                                                                                 new Date (System.currentTimeMillis () +
                                                                                           50000),
                                                                                 nameBuilder.build (),
                                                                                 aKeyPair.getPublic ());

    X509Certificate aX509Certificate = new JcaX509CertificateConverter ().setProvider (PBCProvider.getProvider ())
                                                                         .getCertificate (certGen.build (sigGen));

    aX509Certificate.checkValidity (new Date ());
    aX509Certificate.verify (aKeyPair.getPublic ());

    try (
        final NonBlockingByteArrayInputStream aBAIS = new NonBlockingByteArrayInputStream (aX509Certificate.getEncoded ()))
    {
      final CertificateFactory fact = CertificateFactory.getInstance ("X.509", PBCProvider.getProvider ());
      aX509Certificate = (X509Certificate) fact.generateCertificate (aBAIS);
    }

    log.info (String.valueOf (aX509Certificate));
  }
}
