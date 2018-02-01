package com.helger.asic.extras;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.Collection;

import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;

import com.helger.asic.AsicUtils;
import com.helger.asic.IAsicReader;
import com.helger.asic.jaxb.asic.AsicManifest;

/**
 * Wrapper to seamlessly decode encoded files.
 */
public class CmsEncryptedAsicReader extends CmsEncryptedAsicAbstract implements IAsicReader
{

  private final IAsicReader asicReader;
  private final PrivateKey privateKey;

  private String currentFile;

  public CmsEncryptedAsicReader (final IAsicReader asicReader, final PrivateKey privateKey)
  {
    this.asicReader = asicReader;
    this.privateKey = privateKey;
  }

  @Override
  public String getNextFile () throws IOException
  {
    currentFile = asicReader.getNextFile ();
    if (currentFile == null)
      return null;

    return currentFile.endsWith (".p7m") ? currentFile.substring (0, currentFile.length () - 4) : currentFile;
  }

  @Override
  public void writeFile (final File file) throws IOException
  {
    writeFile (file.toPath ());
  }

  @Override
  public void writeFile (final Path path) throws IOException
  {
    try (OutputStream outputStream = Files.newOutputStream (path))
    {
      writeFile (outputStream);
    }
  }

  @Override
  public void writeFile (final OutputStream outputStream) throws IOException
  {
    if (currentFile.endsWith (".p7m"))
    {
      try
      {
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream ();
        asicReader.writeFile (byteArrayOutputStream);

        final CMSEnvelopedDataParser cmsEnvelopedDataParser = new CMSEnvelopedDataParser (new ByteArrayInputStream (byteArrayOutputStream.toByteArray ()));
        // expect exactly one recipient
        final Collection <?> recipients = cmsEnvelopedDataParser.getRecipientInfos ().getRecipients ();
        if (recipients.size () != 1)
          throw new IllegalArgumentException ();

        // retrieve recipient and decode it
        final RecipientInformation recipient = (RecipientInformation) recipients.iterator ().next ();
        final byte [] decryptedData = recipient.getContent (new JceKeyTransEnvelopedRecipient (privateKey).setProvider (BC));

        AsicUtils.copyStream (new ByteArrayInputStream (decryptedData), outputStream);
      }
      catch (final Exception e)
      {
        throw new IOException (e.getMessage (), e);
      }
    }
    else
    {
      asicReader.writeFile (outputStream);
    }
  }

  @Override
  public InputStream inputStream () throws IOException
  {
    final PipedInputStream pipedInputStream = new PipedInputStream ();
    final PipedOutputStream pipedOutputStream = new PipedOutputStream (pipedInputStream);

    writeFile (pipedOutputStream);
    return pipedInputStream;
  }

  @Override
  public void close () throws IOException
  {
    asicReader.close ();
  }

  @Override
  public AsicManifest getAsicManifest ()
  {
    final AsicManifest asicManifest = asicReader.getAsicManifest ();

    final String rootfile = asicManifest.getRootfile ();
    if (rootfile != null && rootfile.endsWith (".p7m"))
      asicManifest.setRootfile (rootfile.substring (0, rootfile.length () - 4));

    return asicManifest;
  }
}
