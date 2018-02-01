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

  private static JcaSimpleSignerInfoVerifierBuilder jcaSimpleSignerInfoVerifierBuilder = new JcaSimpleSignerInfoVerifierBuilder ().setProvider (BCHelper.getProvider ());

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

        if (signerInformation.verify (jcaSimpleSignerInfoVerifierBuilder.build (x509Certificate)))
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
