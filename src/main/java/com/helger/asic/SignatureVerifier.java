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
import com.helger.commons.annotation.PresentForCodeCoverage;

/**
 * @author erlend
 */
public final class SignatureVerifier
{
  private static final Logger LOG = LoggerFactory.getLogger (SignatureHelper.class);

  private static final JcaSimpleSignerInfoVerifierBuilder s_aJcaSimpleSignerInfoVerifierBuilder = new JcaSimpleSignerInfoVerifierBuilder ().setProvider (BCHelper.getProvider ());

  @PresentForCodeCoverage
  private static final SignatureVerifier s_aInstance = new SignatureVerifier ();

  private SignatureVerifier ()
  {}

  @Nonnull
  public static Certificate validate (final byte [] data, final byte [] signature)
  {
    Certificate ret = null;

    try
    {
      final CMSSignedData cmsSignedData = new CMSSignedData (new CMSProcessableByteArray (data), signature);
      final Store <X509CertificateHolder> store = cmsSignedData.getCertificates ();
      final SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos ();

      for (final SignerInformation aSignerInformation : signerInformationStore.getSigners ())
      {
        final X509CertificateHolder x509Certificate = (X509CertificateHolder) store.getMatches (aSignerInformation.getSID ())
                                                                                   .iterator ()
                                                                                   .next ();
        if (LOG.isDebugEnabled ())
          LOG.debug (x509Certificate.getSubject ().toString ());

        if (aSignerInformation.verify (s_aJcaSimpleSignerInfoVerifierBuilder.build (x509Certificate)))
        {
          ret = new Certificate ();
          ret.setCertificate (x509Certificate.getEncoded ());
          ret.setSubject (x509Certificate.getSubject ().toString ());
        }
      }
    }
    catch (final Exception e)
    {
      LOG.warn ("Error in signature validation", e);
      ret = null;
    }

    if (ret == null)
      throw new IllegalStateException ("Unable to verify signature.");

    return ret;
  }
}
