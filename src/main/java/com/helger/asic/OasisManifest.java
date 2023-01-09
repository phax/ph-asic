/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2023 Philip Helger (www.helger.com)
 * philip[at]helger[dot]com
 *
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/
 */
package com.helger.asic;

import java.io.InputStream;
import java.io.Serializable;

import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.helger.asic.jaxb.AsicReader;
import com.helger.asic.jaxb.AsicWriter;
import com.helger.asic.jaxb.opendocument.manifest.FileEntry;
import com.helger.asic.jaxb.opendocument.manifest.Manifest;
import com.helger.commons.mime.IMimeType;

public class OasisManifest implements Serializable
{
  public static final String NAMESPACE_URI = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";

  private final Manifest m_aManifest;

  public OasisManifest (@Nonnull final IMimeType aMimeType)
  {
    m_aManifest = new Manifest ();
    add ("/", aMimeType);
  }

  public OasisManifest (@Nonnull final InputStream aIS)
  {
    m_aManifest = AsicReader.oasisManifest ().read (aIS);
    if (m_aManifest == null)
      throw new IllegalStateException ("Failed to read Manifest from IS");
  }

  public final void add (@Nonnull final String sPath, @Nonnull final IMimeType aMimeType)
  {
    final FileEntry aEntry = new FileEntry ();
    aEntry.setMediaType (aMimeType.getAsString ());
    aEntry.setFullPath (sPath);
    m_aManifest.getFileEntry ().add (aEntry);
  }

  public void addAll (@Nonnull final OasisManifest aOther)
  {
    for (final FileEntry aEntry : aOther.m_aManifest.getFileEntry ())
      if (!aEntry.getFullPath ().equals ("/"))
        m_aManifest.getFileEntry ().add (aEntry);
  }

  @Nonnegative
  public int getFileEntryCount ()
  {
    return m_aManifest.getFileEntry ().size ();
  }

  @Nullable
  public byte [] getAsBytes ()
  {
    return AsicWriter.oasisManifest ().getAsBytes (m_aManifest);
  }

  @Nullable
  public String getAsString ()
  {
    return AsicWriter.oasisManifest ().getAsString (m_aManifest);
  }
}
