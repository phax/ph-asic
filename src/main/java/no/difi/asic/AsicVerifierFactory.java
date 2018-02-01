package no.difi.asic;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class AsicVerifierFactory
{
  private final EMessageDigestAlgorithm m_eMessageDigestAlgorithm;

  public static AsicVerifierFactory newFactory ()
  {
    return newFactory (EMessageDigestAlgorithm.SHA256);
  }

  public static AsicVerifierFactory newFactory (final ESignatureMethod signatureMethod)
  {
    return newFactory (signatureMethod.getMessageDigestAlgorithm ());
  }

  static AsicVerifierFactory newFactory (final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    return new AsicVerifierFactory (messageDigestAlgorithm);
  }

  private AsicVerifierFactory (final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    this.m_eMessageDigestAlgorithm = messageDigestAlgorithm;
  }

  public AsicVerifier verify (final File file) throws IOException
  {
    return verify (file.toPath ());
  }

  public AsicVerifier verify (final Path file) throws IOException
  {
    return verify (Files.newInputStream (file));
  }

  public AsicVerifier verify (final InputStream inputStream) throws IOException
  {
    return new AsicVerifier (m_eMessageDigestAlgorithm, inputStream);
  }
}
