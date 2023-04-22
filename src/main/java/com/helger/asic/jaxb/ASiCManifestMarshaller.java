package com.helger.asic.jaxb;

import java.util.List;

import com.helger.asic.jaxb.cades.ASiCManifestType;
import com.helger.asic.jaxb.cades.ObjectFactory;
import com.helger.commons.collection.impl.CommonsArrayList;
import com.helger.commons.io.resource.ClassPathResource;
import com.helger.jaxb.GenericJAXBMarshaller;
import com.helger.xsds.xmldsig.CXMLDSig;

/**
 * JAXB marshaller for the {@link ASiCManifestType}.
 *
 * @author Philip Helger
 * @since 3.0.0
 */
public class ASiCManifestMarshaller extends GenericJAXBMarshaller <ASiCManifestType>
{
  public static final List <ClassPathResource> XSDS = new CommonsArrayList <> (CXMLDSig.getXSDResource (),
                                                                               new ClassPathResource ("external/schemas/ts_102918v010201.xsd",
                                                                                                      ASiCManifestMarshaller.class.getClassLoader ())).getAsUnmodifiable ();

  public ASiCManifestMarshaller ()
  {
    super (ASiCManifestType.class, XSDS, new ObjectFactory ()::createASiCManifest);
    setFormattedOutput (true);
  }
}
