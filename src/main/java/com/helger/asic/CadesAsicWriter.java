package com.helger.asic;

import java.io.IOException;
import java.io.OutputStream;
import java.util.UUID;

/**
 * Builds an ASiC-E Cades container using a variation of "builder pattern". This
 * class is not thread safe, as it indirectly holds a MessageDigest object.
 *
 * @author steinar Date: 02.07.15 Time: 12.09
 */
public class CadesAsicWriter extends AbstractAsicWriter
{

  /**
   * Prepares creation of a new container.
   *
   * @param signatureMethod
   *        signature method
   * @param outputStream
   *        Stream used to write container.
   * @param closeStreamOnClose
   *        close stream when this is closed
   * @throws IOException
   *         on IO error
   */
  public CadesAsicWriter (final ESignatureMethod signatureMethod,
                          final OutputStream outputStream,
                          final boolean closeStreamOnClose) throws IOException
  {
    super (outputStream, closeStreamOnClose, new CadesAsicManifest (signatureMethod.getMessageDigestAlgorithm ()));
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public IAsicWriter setRootEntryName (final String name)
  {
    ((CadesAsicManifest) m_aAsicManifest).setRootfileForEntry (name);
    return this;
  }

  @Override
  protected void performSign (final SignatureHelper signatureHelper) throws IOException
  {
    // Define signature filename containing UUID
    final String signatureFilename = String.format ("META-INF/signature-%s.p7s", UUID.randomUUID ().toString ());

    // Adding signature file to asic manifest before actual signing
    ((CadesAsicManifest) m_aAsicManifest).setSignature (signatureFilename, "application/x-pkcs7-signature");

    // Generates and writes manifest (META-INF/asicmanifest.xml) to the zip
    // archive
    final byte [] manifestBytes = ((CadesAsicManifest) m_aAsicManifest).toBytes ();
    m_aAsicOutputStream.writeZipEntry ("META-INF/asicmanifest.xml", manifestBytes);

    // Generates and writes signature (META-INF/signature-*.p7s) to the zip
    // archive
    m_aAsicOutputStream.writeZipEntry (signatureFilename, signatureHelper.signData (manifestBytes));
  }
}
