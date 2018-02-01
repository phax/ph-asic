package no.difi.asic;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Creates AsicWriter instances according to the supplied parameters.
 */
public class AsicWriterFactory
{
  private static final Logger logger = LoggerFactory.getLogger (AsicWriterFactory.class);

  /**
   * Creates an AsicWriterFactory, which utilises the default signature method,
   * which is currently CAdES.
   *
   * @return instantiated AsicWriterFactory
   */
  public static AsicWriterFactory newFactory ()
  {
    return newFactory (ESignatureMethod.CAdES);
  }

  /**
   * Creates an AsicWriterFactory using the supplied signature method.
   *
   * @param signatureMethod
   *        the signature method to be used.
   * @return instantiated AsicWriterFactory
   * @see ESignatureMethod
   */
  public static AsicWriterFactory newFactory (final ESignatureMethod signatureMethod)
  {
    return new AsicWriterFactory (signatureMethod);
  }

  private final ESignatureMethod m_eSM;

  private AsicWriterFactory (final ESignatureMethod signatureMethod)
  {
    this.m_eSM = signatureMethod;
  }

  /**
   * Factory method creating a new AsicWriter, which will create an ASiC archive
   * in the supplied directory with the supplied file name
   *
   * @param outputDir
   *        the directory in which the archive will be created.
   * @param filename
   *        the name of the archive.
   * @return an instance of AsicWriter
   * @throws IOException
   */
  public IAsicWriter newContainer (final File outputDir, final String filename) throws IOException
  {
    return newContainer (new File (outputDir, filename));
  }

  /**
   * Creates a new AsicWriter, which will create an ASiC archive in the supplied
   * file.
   *
   * @param file
   *        the file reference to the archive.
   * @return an instance of AsicWriter
   * @throws IOException
   */
  public IAsicWriter newContainer (final File file) throws IOException
  {
    return newContainer (file.toPath ());
  }

  /**
   * @see #newContainer(File)
   */
  public IAsicWriter newContainer (final Path path) throws IOException
  {
    // Conformance to ETSI TS 102 918, 6.2.1 1)
    if (!AsicUtils.PATTERN_EXTENSION_ASICE.matcher (path.toString ()).matches ())
      logger.warn ("ASiC-E files should use \"asice\" as file extension.");

    return newContainer (Files.newOutputStream (path), true);
  }

  /**
   * Creates a new AsicWriter, which will write the container contents to the
   * supplied output stream.
   *
   * @param outputStream
   *        stream into which the archive will be written.
   * @return an instance of AsicWriter
   * @throws IOException
   */
  public IAsicWriter newContainer (final OutputStream outputStream) throws IOException
  {
    return newContainer (outputStream, false);
  }

  IAsicWriter newContainer (final OutputStream outputStream, final boolean closeStreamOnClose) throws IOException
  {
    switch (m_eSM)
    {
      case CAdES:
        return new CadesAsicWriter (m_eSM, outputStream, closeStreamOnClose);
      case XAdES:
        return new XadesAsicWriter (m_eSM, outputStream, closeStreamOnClose);
      default:
        throw new IllegalStateException (String.format ("Not implemented: %s", m_eSM));
    }
  }
}
