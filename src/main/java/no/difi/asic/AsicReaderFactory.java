package no.difi.asic;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class AsicReaderFactory
{

  public static AsicReaderFactory newFactory ()
  {
    return newFactory (EMessageDigestAlgorithm.SHA256);
  }

  public static AsicReaderFactory newFactory (ESignatureMethod signatureMethod)
  {
    return newFactory (signatureMethod.getMessageDigestAlgorithm ());
  }

  static AsicReaderFactory newFactory (EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    return new AsicReaderFactory (messageDigestAlgorithm);
  }

  private EMessageDigestAlgorithm m_eMD;

  private AsicReaderFactory (EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    this.m_eMD = messageDigestAlgorithm;
  }

  public IAsicReader open (File file) throws IOException
  {
    return open (file.toPath ());
  }

  public IAsicReader open (Path file) throws IOException
  {
    return open (Files.newInputStream (file));
  }

  public IAsicReader open (InputStream inputStream) throws IOException
  {
    return new AsicReaderImpl (m_eMD, inputStream);
  }
}
