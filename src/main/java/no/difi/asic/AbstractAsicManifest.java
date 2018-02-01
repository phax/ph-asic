package no.difi.asic;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.annotation.Nonnull;

abstract class AbstractAsicManifest
{
  protected EMessageDigestAlgorithm m_aMessageDigestAlgorithm;
  protected MessageDigest m_aMD;

  public AbstractAsicManifest (@Nonnull final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    m_aMessageDigestAlgorithm = messageDigestAlgorithm;

    // Create message digest
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
  }

  @Nonnull
  public MessageDigest getMessageDigest ()
  {
    m_aMD.reset ();
    return m_aMD;
  }

  /**
   * @inheritDoc
   */
  public abstract void add (String filename, MimeType mimeType);
}
