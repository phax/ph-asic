package no.difi.asic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.ZipEntry;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.collection.impl.CommonsHashMap;
import com.helger.commons.collection.impl.ICommonsMap;
import com.helger.commons.io.stream.NullOutputStream;
import com.helger.commons.io.stream.StreamHelper;

import no.difi.commons.asic.jaxb.asic.AsicManifest;
import no.difi.commons.asic.jaxb.asic.Certificate;
import no.difi.commons.asic.jaxb.opendocument.manifest.Manifest;

/**
 * Skeleton implementation of ASiC archive reader.
 *
 * @author Erlend Klakegg Bergheim
 */
abstract class AbstractAsicReader implements Closeable
{
  private static final Logger logger = LoggerFactory.getLogger (AbstractAsicReader.class);

  private MessageDigest m_aMD;

  private AsicInputStream m_aZipInputStream;
  private ZipEntry m_aCurrentZipEntry;

  private final ManifestVerifier m_aManifestVerifier;
  private Manifest m_aManifest;

  // Initiated with 'true' as the first file should not do anything.
  private boolean m_bContentIsWritten = true;

  /**
   * Used to hold signature or manifest for CAdES as they are not in the same
   * file.
   */
  private final ICommonsMap <String, Object> m_aSigningContent = new CommonsHashMap <> ();

  AbstractAsicReader (final EMessageDigestAlgorithm messageDigestAlgorithm, final InputStream inputStream)
  {
    m_aManifestVerifier = new ManifestVerifier (messageDigestAlgorithm);

    try
    {
      m_aMD = MessageDigest.getInstance (messageDigestAlgorithm.getAlgorithm ());
      m_aMD.reset ();
    }
    catch (final NoSuchAlgorithmException e)
    {
      throw new IllegalStateException (String.format ("Algorithm %s not supported",
                                                      messageDigestAlgorithm.getAlgorithm ()),
                                       e);
    }

    m_aZipInputStream = new AsicInputStream (inputStream);
    // Comment in ZIP is stored in Central Directory in the end of the file.
  }

  public String getNextFile () throws IOException
  {
    // Read file if the user didn't.
    if (!m_bContentIsWritten)
      writeFile (new NullOutputStream ());

    // Write digest to manifest
    if (m_aCurrentZipEntry != null)
    {
      final byte [] digest = m_aMD.digest ();
      logger.debug ("Digest: {}", Base64.encode (digest));
      m_aManifestVerifier.update (m_aCurrentZipEntry.getName (), digest, null);
    }

    while ((m_aCurrentZipEntry = m_aZipInputStream.getNextEntry ()) != null)
    {
      logger.info ("Found file: {}", m_aCurrentZipEntry.getName ());

      // Files used for validation are not exposed
      if (m_aCurrentZipEntry.getName ().startsWith ("META-INF/"))
        handleMetadataEntry ();
      else
      {
        m_bContentIsWritten = false;
        return m_aCurrentZipEntry.getName ();
      }
    }

    // Making sure signatures are used and all files are signed after reading
    // all content.

    // All files must be signed by minimum one manifest/signature.
    m_aManifestVerifier.verifyAllVerified ();

    // All CAdES signatures and manifest must be verified.
    if (m_aSigningContent.size () > 0)
      throw new IllegalStateException (String.format ("Signature not verified: %s",
                                                      m_aSigningContent.keySet ().iterator ().next ()));

    // Return null when container is out of content to read.
    return null;
  }

  void writeFile (final OutputStream outputStream) throws IOException
  {
    if (m_aCurrentZipEntry == null)
      throw new IllegalStateException ("No file to read.");

    // Calculate digest while reading file
    m_aMD.reset ();
    final DigestOutputStream digestOutputStream = new DigestOutputStream (outputStream, m_aMD);
    AsicUtils.copyStream (m_aZipInputStream, digestOutputStream);

    m_aZipInputStream.closeEntry ();

    m_bContentIsWritten = true;
  }

  InputStream inputStream ()
  {
    if (m_aCurrentZipEntry == null)
      throw new IllegalStateException ("No file to read.");

    // We must trust the user.
    m_bContentIsWritten = true;

    m_aMD.reset ();
    // Why wrapping??
    return new InputStreamWrapper (new DigestInputStream (m_aZipInputStream, m_aMD));
  }

  @Override
  public void close () throws IOException
  {
    StreamHelper.close (m_aZipInputStream);
    m_aZipInputStream = null;
  }

  /**
   * Handles zip entries in the META-INF/ directory.
   *
   * @throws IOException
   */
  private void handleMetadataEntry () throws IOException
  {
    // Extracts everything after META-INF/
    final String filename = m_aCurrentZipEntry.getName ().substring (9).toLowerCase ();

    // Read content in file
    final ByteArrayOutputStream contentsOfStream = new ByteArrayOutputStream ();
    AsicUtils.copyStream (m_aZipInputStream, contentsOfStream);

    if (AsicUtils.PATTERN_CADES_MANIFEST.matcher (m_aCurrentZipEntry.getName ()).matches ())
    {
      // Handling manifest in ASiC CAdES.
      final String sigReference = CadesAsicManifest.extractAndVerify (contentsOfStream.toString (),
                                                                      m_aManifestVerifier);
      handleCadesSigning (sigReference, contentsOfStream.toString ());
    }
    else
      if (AsicUtils.PATTERN_XADES_SIGNATURES.matcher (m_aCurrentZipEntry.getName ()).matches ())
      {
        // Handling manifest in ASiC XAdES.
        XadesAsicManifest.extractAndVerify (contentsOfStream.toString (), m_aManifestVerifier);
      }
      else
        if (AsicUtils.PATTERN_CADES_SIGNATURE.matcher (m_aCurrentZipEntry.getName ()).matches ())
        {
          // Handling signature in ASiC CAdES.
          handleCadesSigning (m_aCurrentZipEntry.getName (), contentsOfStream);
        }
        else
          if (filename.equals ("manifest.xml"))
          {
            // Read manifest.
            m_aManifest = OasisManifest.read (new ByteArrayInputStream (contentsOfStream.toByteArray ()));
          }
          else
          {
            throw new IllegalStateException (String.format ("Contains unknown metadata file: %s",
                                                            m_aCurrentZipEntry.getName ()));
          }
  }

  private void handleCadesSigning (final String sigReference, final Object o)
  {
    if (!m_aSigningContent.containsKey (sigReference))
      m_aSigningContent.put (sigReference, o);
    else
    {
      final byte [] data = o instanceof String ? ((String) o).getBytes ()
                                               : ((String) m_aSigningContent.get (sigReference)).getBytes ();
      final byte [] sign = o instanceof ByteArrayOutputStream ? ((ByteArrayOutputStream) o).toByteArray ()
                                                              : ((ByteArrayOutputStream) m_aSigningContent.get (sigReference)).toByteArray ();

      final Certificate certificate = SignatureVerifier.validate (data, sign);
      certificate.setCert (m_aCurrentZipEntry.getName ());
      m_aManifestVerifier.addCertificate (certificate);

      m_aSigningContent.remove (sigReference);
    }
  }

  /**
   * Property getter for the AsicManifest of the ASiC archive.
   *
   * @return value of property.
   */
  public AsicManifest getAsicManifest ()
  {
    return m_aManifestVerifier.getAsicManifest ();
  }

  /**
   * Property getter for the OpenDocument manifest.
   *
   * @return value of property, null if document is not found in container.
   */
  public Manifest getOasisManifest ()
  {
    return m_aManifest;
  }

}
