package com.helger.asic;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import com.helger.asic.jaxb.asic.AsicFile;
import com.helger.asic.jaxb.asic.AsicManifest;
import com.helger.asic.jaxb.asic.Certificate;

class ManifestVerifier
{

  private final EMessageDigestAlgorithm messageDigestAlgorithm;

  private final AsicManifest asicManifest = new AsicManifest ();
  private final Map <String, AsicFile> asicManifestMap = new HashMap <> ();

  public ManifestVerifier (final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    this.messageDigestAlgorithm = messageDigestAlgorithm;
  }

  public void update (final String filename, final byte [] digest, final String sigReference)
  {
    update (filename, null, digest, null, sigReference);
  }

  public void update (final String filename,
                      final String mimetype,
                      final byte [] digest,
                      final String digestAlgorithm,
                      final String sigReference)
  {
    if (messageDigestAlgorithm != null &&
        digestAlgorithm != null &&
        !digestAlgorithm.equals (messageDigestAlgorithm.getUri ()))
      throw new IllegalStateException (String.format ("Wrong digest method for file %s: %s",
                                                      filename,
                                                      digestAlgorithm));

    AsicFile asicFile = asicManifestMap.get (filename);

    if (asicFile == null)
    {
      asicFile = new AsicFile ();
      asicFile.setName (filename);
      asicFile.setDigest (digest);
      asicFile.setVerified (false);

      asicManifest.getFile ().add (asicFile);
      asicManifestMap.put (filename, asicFile);
    }
    else
    {
      if (!Arrays.equals (asicFile.getDigest (), digest))
        throw new IllegalStateException (String.format ("Mismatching digest for file %s", filename));

      asicFile.setVerified (true);
    }

    if (mimetype != null)
      asicFile.setMimetype (mimetype);
    if (sigReference != null)
      asicFile.getCertRef ().add (sigReference);

  }

  public void addCertificate (final Certificate certificate)
  {
    this.asicManifest.getCertificate ().add (certificate);
  }

  public void setRootFilename (final String filename)
  {
    asicManifest.setRootfile (filename);
  }

  public void verifyAllVerified ()
  {
    for (final AsicFile asicFile : asicManifest.getFile ())
      if (!asicFile.isVerified ())
        throw new IllegalStateException (String.format ("File not verified: %s", asicFile.getName ()));
  }

  public AsicManifest getAsicManifest ()
  {
    return asicManifest;
  }
}
