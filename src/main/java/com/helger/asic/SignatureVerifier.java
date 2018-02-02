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

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.asic.jaxb.asic.Certificate;

/**
 * @author erlend
 */
public class SignatureVerifier
{
  private static final Logger logger = LoggerFactory.getLogger (SignatureHelper.class);

  private static JcaSimpleSignerInfoVerifierBuilder s_aJcaSimpleSignerInfoVerifierBuilder = new JcaSimpleSignerInfoVerifierBuilder ().setProvider (BCHelper.getProvider ());

  private SignatureVerifier ()
  {}

  public static Certificate validate (final byte [] data, final byte [] signature)
  {
    Certificate certificate = null;

    try
    {
      final CMSSignedData cmsSignedData = new CMSSignedData (new CMSProcessableByteArray (data), signature);
      final Store <X509CertificateHolder> store = cmsSignedData.getCertificates ();
      final SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos ();

      for (final SignerInformation signerInformation : signerInformationStore.getSigners ())
      {
        final X509CertificateHolder x509Certificate = (X509CertificateHolder) store.getMatches (signerInformation.getSID ())
                                                                                   .iterator ()
                                                                                   .next ();
        logger.info (x509Certificate.getSubject ().toString ());

        if (signerInformation.verify (s_aJcaSimpleSignerInfoVerifierBuilder.build (x509Certificate)))
        {
          certificate = new Certificate ();
          certificate.setCertificate (x509Certificate.getEncoded ());
          certificate.setSubject (x509Certificate.getSubject ().toString ());
        }
      }
    }
    catch (final Exception e)
    {
      logger.warn (e.getMessage ());
      certificate = null;
    }

    if (certificate == null)
      throw new IllegalStateException ("Unable to verify signature.");

    return certificate;
  }
}
