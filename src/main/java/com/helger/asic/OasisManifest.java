package com.helger.asic;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import com.helger.asic.jaxb.opendocument.manifest.FileEntry;
import com.helger.asic.jaxb.opendocument.manifest.Manifest;

class OasisManifest
{

  private static JAXBContext jaxbContext; // Thread safe

  static
  {
    try
    {
      jaxbContext = JAXBContext.newInstance (Manifest.class);
    }
    catch (final JAXBException e)
    {
      throw new IllegalStateException (String.format ("Unable to create JAXBContext: %s ", e.getMessage ()), e);
    }
  }

  public static Manifest read (final InputStream inputStream)
  {
    return new OasisManifest (inputStream).getManifest ();
  }

  private Manifest manifest = new Manifest ();

  public OasisManifest (final MimeType mimeType)
  {
    add ("/", mimeType);
  }

  public OasisManifest (final InputStream inputStream)
  {
    try
    {
      final Unmarshaller unmarshaller = jaxbContext.createUnmarshaller ();
      manifest = (Manifest) unmarshaller.unmarshal (inputStream);
    }
    catch (final JAXBException e)
    {
      throw new IllegalStateException ("Unable to read XML as OASIS OpenDocument Manifest.", e);
    }
  }

  public void add (final String path, final MimeType mimeType)
  {
    final FileEntry fileEntry = new FileEntry ();
    fileEntry.setMediaType (mimeType.toString ());
    fileEntry.setFullPath (path);
    manifest.getFileEntry ().add (fileEntry);
  }

  public void append (final OasisManifest oasisManifest)
  {
    for (final FileEntry fileEntry : oasisManifest.getManifest ().getFileEntry ())
      if (!fileEntry.getFullPath ().equals ("/"))
        manifest.getFileEntry ().add (fileEntry);
  }

  public int size ()
  {
    return manifest.getFileEntry ().size ();
  }

  public Manifest getManifest ()
  {
    return manifest;
  }

  public byte [] toBytes ()
  {
    try
    {
      final Marshaller marshaller = jaxbContext.createMarshaller ();
      marshaller.setProperty (Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

      final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream ();
      marshaller.marshal (manifest, byteArrayOutputStream);

      return byteArrayOutputStream.toByteArray ();
    }
    catch (final JAXBException e)
    {
      throw new IllegalStateException ("Unable to create OASIS OpenDocument Manifest.", e);
    }
  }
}
