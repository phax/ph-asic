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

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.base.codec.base64.Base64;
import com.helger.bc.PBCProvider;

/**
 * @author steinar Date: 05.07.15 Time: 21.57
 */
public final class BouncyCastleSignatureTest
{
  private static final Logger LOGGER = LoggerFactory.getLogger (BouncyCastleSignatureTest.class);

  @Test
  public void createSignature () throws Exception
  {
    // Reads private key and certificate from our own
    // keystore
    final SignatureHelper aSH = TestUtil.createSH ();
    final X509Certificate aX509Certificate = aSH.getX509Certificate ();
    final KeyPair aKeyPair = aSH.getKeyPair ();

    final String keyAlgorithm = aKeyPair.getPrivate ().getAlgorithm ();

    for (final EMessageDigestAlgorithm e : EMessageDigestAlgorithm.values ())
    {
      final CMSProcessableByteArray msg = new CMSProcessableByteArray ("Hello world".getBytes (StandardCharsets.ISO_8859_1));

      final List <?> certList = new ArrayList <> ();
      final JcaCertStore jcaCertStore = new JcaCertStore (certList);
      final CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator ();
      final ContentSigner contentSigner = new JcaContentSignerBuilder (e.getContentSignerAlgorithm () +
                                                                       "with" +
                                                                       keyAlgorithm).setProvider (PBCProvider.getProvider ())
                                                                                    .build (aKeyPair.getPrivate ());

      final DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder ().setProvider (PBCProvider.getProvider ())
                                                                                                         .build ();
      final SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder (digestCalculatorProvider).build (contentSigner,
                                                                                                                          aX509Certificate);
      cmsSignedDataGenerator.addSignerInfoGenerator (signerInfoGenerator);
      cmsSignedDataGenerator.addCertificates (jcaCertStore);
      final CMSSignedData sigData = cmsSignedDataGenerator.generate (msg, false);

      LOGGER.info (e + ": " + Base64.encodeBytes (sigData.getEncoded ()));
    }
  }
}
