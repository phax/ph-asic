package no.difi.asic;

import java.io.IOException;
import java.io.OutputStream;
import java.util.UUID;

/**
 * Builds an ASiC-E Cades container using a variation of "builder pattern". This
 * class is not thread safe, as it indirectly holds a MessageDigest object.
 *
 * @author steinar Date: 02.07.15 Time: 12.09
 */
class CadesAsicWriter extends AbstractAsicWriter
{

  /**
   * Prepares creation of a new container.
   * 
   * @param outputStream
   *        Stream used to write container.
   */
  public CadesAsicWriter (ESignatureMethod signatureMethod,
                          OutputStream outputStream,
                          boolean closeStreamOnClose) throws IOException
  {
    super (outputStream, closeStreamOnClose, new CadesAsicManifest (signatureMethod.getMessageDigestAlgorithm ()));
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public IAsicWriter setRootEntryName (String name)
  {
    ((CadesAsicManifest) m_aAsicManifest).setRootfileForEntry (name);
    return this;
  }

  @Override
  protected void performSign (SignatureHelper signatureHelper) throws IOException
  {
    // Define signature filename containing UUID
    String signatureFilename = String.format ("META-INF/signature-%s.p7s", UUID.randomUUID ().toString ());

    // Adding signature file to asic manifest before actual signing
    ((CadesAsicManifest) m_aAsicManifest).setSignature (signatureFilename, "application/x-pkcs7-signature");

    // Generates and writes manifest (META-INF/asicmanifest.xml) to the zip
    // archive
    byte [] manifestBytes = ((CadesAsicManifest) m_aAsicManifest).toBytes ();
    m_aAsicOutputStream.writeZipEntry ("META-INF/asicmanifest.xml", manifestBytes);

    // Generates and writes signature (META-INF/signature-*.p7s) to the zip
    // archive
    m_aAsicOutputStream.writeZipEntry (signatureFilename, signatureHelper.signData (manifestBytes));
  }
}
