/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2019 Philip Helger (www.helger.com)
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
import com.helger.bc.PBCProvider;
import com.helger.commons.annotation.PresentForCodeCoverage;
import com.helger.commons.timing.StopWatch;

/**
 * @author erlend
 */
public final class SignatureVerifier
{
  private static final Logger LOG = LoggerFactory.getLogger (SignatureHelper.class);

  private static final JcaSimpleSignerInfoVerifierBuilder s_aJcaSimpleSignerInfoVerifierBuilder = new JcaSimpleSignerInfoVerifierBuilder ().setProvider (PBCProvider.getProvider ());

  @PresentForCodeCoverage
  private static final SignatureVerifier s_aInstance = new SignatureVerifier ();

  private SignatureVerifier ()
  {}

  @Nonnull
  public static Certificate validate (@Nonnull final byte [] aData, @Nonnull final byte [] aSignature)
  {
    Certificate ret = null;

    if (LOG.isDebugEnabled ())
      LOG.debug ("Starting to validate signature of data");

    final StopWatch aSW = StopWatch.createdStarted ();
    try
    {
      final CMSSignedData aCMSSignedData = new CMSSignedData (new CMSProcessableByteArray (aData), aSignature);

      if (LOG.isDebugEnabled ())
        LOG.debug ("Received the signed data");

      final Store <X509CertificateHolder> aStore = aCMSSignedData.getCertificates ();
      final SignerInformationStore aSignerInformationStore = aCMSSignedData.getSignerInfos ();
      for (final SignerInformation aSignerInformation : aSignerInformationStore.getSigners ())
      {
        final X509CertificateHolder aX509CertHolder = (X509CertificateHolder) aStore.getMatches (aSignerInformation.getSID ())
                                                                                    .iterator ()
                                                                                    .next ();
        if (LOG.isDebugEnabled ())
          LOG.debug ("Using certificate subject " +
                     (aX509CertHolder == null ? "null" : "'" + aX509CertHolder.getSubject ().toString () + "'") +
                     " for '" +
                     aSignerInformation.getSID () +
                     "'");

        if (aSignerInformation.verify (s_aJcaSimpleSignerInfoVerifierBuilder.build (aX509CertHolder)))
        {
          ret = new Certificate ();
          ret.setCertificate (aX509CertHolder.getEncoded ());
          ret.setSubject (aX509CertHolder.getSubject ().toString ());
          break;
        }
      }
    }
    catch (final Exception ex)
    {
      LOG.warn ("Error in signature validation", ex);
      ret = null;
    }
    finally
    {
      final long nMillis = aSW.stopAndGetMillis ();
      if (nMillis > 100)
        LOG.warn ("Certificate validation took " + nMillis + " which is too long");
    }
    if (ret == null)
      throw new IllegalStateException ("Unable to verify signature. See log for details");
    return ret;
  }
}
