package com.helger.asic;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.annotation.Nonnull;

public class AsicReaderFactory
{
  @Nonnull
  public static AsicReaderFactory newFactory ()
  {
    return newFactory (EMessageDigestAlgorithm.SHA256);
  }

  @Nonnull
  public static AsicReaderFactory newFactory (final ESignatureMethod signatureMethod)
  {
    return newFactory (signatureMethod.getMessageDigestAlgorithm ());
  }

  @Nonnull
  static AsicReaderFactory newFactory (final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    return new AsicReaderFactory (messageDigestAlgorithm);
  }

  private final EMessageDigestAlgorithm m_eMD;

  protected AsicReaderFactory (@Nonnull final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    m_eMD = messageDigestAlgorithm;
  }

  @Nonnull
  public IAsicReader open (@Nonnull final File file) throws IOException
  {
    return open (file.toPath ());
  }

  @Nonnull
  public IAsicReader open (@Nonnull final Path file) throws IOException
  {
    return open (Files.newInputStream (file));
  }

  @Nonnull
  public IAsicReader open (@Nonnull final InputStream inputStream) throws IOException
  {
    return new AsicReaderImpl (m_eMD, inputStream);
  }
}
