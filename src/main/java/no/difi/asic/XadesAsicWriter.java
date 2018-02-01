package no.difi.asic;

import java.io.IOException;
import java.io.OutputStream;

public class XadesAsicWriter extends AbstractAsicWriter
{
  public XadesAsicWriter (final ESignatureMethod signatureMethod,
                          final OutputStream outputStream,
                          final boolean closeStreamOnClose) throws IOException
  {
    super (outputStream, closeStreamOnClose, new XadesAsicManifest (signatureMethod.getMessageDigestAlgorithm ()));
  }

  @Override
  public IAsicWriter setRootEntryName (final String name)
  {
    throw new IllegalStateException ("ASiC-E XAdES does not support defining root file.");
  }

  @Override
  protected void performSign (final SignatureHelper signatureHelper) throws IOException
  {
    // Generate and write manifest (META-INF/signatures.xml)
    final byte [] manifestBytes = ((XadesAsicManifest) m_aAsicManifest).toBytes (signatureHelper);
    m_aAsicOutputStream.writeZipEntry ("META-INF/signatures.xml", manifestBytes);

    // System.out.println(new String(manifestBytes));
  }
}
