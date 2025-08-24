# ph-asic

[![Maven Central](https://img.shields.io/maven-central/v/com.helger/ph-asic.svg)](http://search.maven.org/#search%7Cgav%7C1%7Cg%3A%22com.helger%22%20AND%20a%3A%22ph-asic%22)
[![javadoc](https://javadoc.io/badge2/com.helger/ph-asic/javadoc.svg)](https://javadoc.io/doc/com.helger/ph-asic)
[![CodeCov](https://codecov.io/gh/phax/ph-asic/branch/master/graph/badge.svg)](https://codecov.io/gh/phax/ph-asic)

# News and Noteworthy

v4.0.0 - 2025-08-24
* Requires Java 17 as the minimum version
* Updated to ph-commons 12.0.0
* Removed all deprecated methods marked for removal

v3.0.1 - 2024-11-10
* Updated to ph-commons 11.1.10
* Switched JAXB Maven plugin to `org.jvnet.jaxb:jaxb-maven-plugin`
* Made `AsicReaderFactory.newFactory` public

v3.0.0 - 2023-04-22
* Deprecated classes `Asic(Reader|Writer|Validator)` and `EAsicDocumentType` in favour separate marshallers
* Moved XML schema to folder `external/...`

v2.0.0 - 2023-01-08
* Using Java 11 as the baseline
* Updated to ph-commons 11
* Using JAXB 4.0 as the baseline

v1.7.0 - 2021-05-02
* Updated to ph-commons 10.1

v1.6.0 - 2021-03-21
* Updated to ph-commons 10

v1.5.4 - 2021-03-18
* Updated to ph-commons 9.5.5
* Updated to ph-xsds 2.4.3

v1.5.3 - 2020-09-17
* Updated to Jakarta JAXB 2.3.3

v1.5.2 - 2020-08-28
* Updated to ph-xsds 2.4.0

v1.5.1 - 2020-05-26
* Updated to ph-xsds 2.3.0 (changed Maven groupId)

v1.5.0 - 2019-11-22
* Fixed naming of Cades manifest file from `asicmanifest.xml` to `ASiCManifest.xml` ([issue #3](https://github.com/phax/ph-asic/issues/3))
* Fixed ([issue #4](https://github.com/phax/ph-asic/issues/4)) and ([issue #5](https://github.com/phax/ph-asic/issues/5)) using ([PR #6](https://github.com/phax/ph-asic/pull/6))
* Made the creation of the OASIS Open Document optional ([issue #7](https://github.com/phax/ph-asic/issues/7))

v1.4.0 - 2019-10-24
* Removed hard coded "SHA1" in CAdES Signature method ([issue #1](https://github.com/phax/ph-asic/issues/1))
* Removed all utility methods from `ESignatureMethod`
* Removed factory methods using `ESignatureMethod`
* Added new constant `EMessageDigestAlgorithm.DEFAULT` which is now "SHA-256"
* Extended `EMessageDigestAlgorithm` with "SHA1" and "SHA224"
* Fixed invalid URI for `EMessageDigestAlgorithm.SHA384`
* Renamed `EMessageDigestAlgorithm.getAlgorithm` to `getMessageDigestAlgorithm`
* Constructors of `CadesAsicWriter` and `XadesAsicWriter` now take the message digest algorithm instead of the `ESignatureMethod`

v1.3.1 - 2019-05-07
* Updated to Java 12

v1.3.0 - 2018-11-22
* Updated to ph-commons 9.2.0

v1.2.0 - 2018-07-10
* Changed SignatureHelper API to be more precise and to load keystores from different sources

v1.1.0 - 2018-06-20
* Updated to ph-commons 9.1.2

v1.0.2 - 2018-06-13
* Fixed dependency to external XMLSchema.dtd

v1.0.1 - 2018-02-20
* Less verbose logging
* Improved speed

v1.0.0 - 2018-02-13
* Initial version as rip of difi/asic

# Associated Signature Container (ASiC)

An ASiC file is simply a ZIP archive created according to some rules set forth in the specifications. 

The benefits of using containers for message transfer are:
* all files are kept together as a single collection.
* very efficient with regards to space.
* due to the compressed format, communication bandwidth is utilized better
* message integrity is provided, using message digests and signatures.
* confidentiality is provided by encryption using AES-256 in GCM mode

This component provides an easy-to-use factory for creating ASiC-E containers.

Conformance is claimed according to 7.2.1 (TBA) and 7.2.2 in
[ETSI TS 102 918 V1.3.1](http://webapp.etsi.org/workprogram/Report_WorkItem.asp?WKI_ID=42455).

This implementation is based on difi's v0.9.2

## Maven

Replace `x.y.z` with the real version number.

```xml
<dependency>
	<groupId>com.helger</groupId>
	<artifactId>ph-asic</artifactId>
	<version>x.y.z</version>
</dependency>
```

## Gradle considerations

This project relies on JDK version based Maven profile activation.
See https://github.com/phax/ph-jaxb-pom#gradle-usage for help on this specific issue. 

## What does it look like?

In general the archive looks something like depicted below 

```
asic-container.asice: 
   |
   +-- mimetype
   |
   +-- bii-envelope.xml
   |
   +-- bii-document.xml
   |
   +-- META-INF/
          |
          + asicmanifest.xml
          |
          + signature.p7s   
   
```

Consult the [AsicCadesContainerWriterTest](src/test/java/no/phax/ph-asic/AsicWriterTest.java) for sample usage.
Here is a rough sketch on how to do it:
```java
// Creates an ASiC archive after which every entry is read back from the archive.

// Name of the file to hold the the ASiC archive
File archiveOutputFile = new File(System.getProperty("java.io.tmpdir"), "asic-sample-default.zip");

// Creates an AsicWriterFactory with default signature method
AsicWriterFactory asicWriterFactory = AsicWriterFactory.newFactory();

// Creates the actual container with all the data objects (files) and signs it.
AsicWriter asicWriter = asicWriterFactory.newContainer(archiveOutputFile)
        // Adds an ordinary file, using the file name as the entry name
        .add(biiEnvelopeFile)
                // Adds another file, explicitly naming the entry and specifying the MIME type
        .add(biiMessageFile, BII_MESSAGE_XML, MimeType.forString("application/xml"))
                // Signing the contents of the archive, closes it for further changes.
        .sign(keystoreFile, TestUtil.keyStorePassword(), TestUtil.privateKeyPassword());

// Opens the generated archive and reads each entry
AsicReader asicReader = AsicReaderFactory.newFactory().open(archiveOutputFile);

String entryName;

// Iterates over each entry and writes the contents into a file having same name as the entry
while ((entryName = asicReader.getNextFile()) != null) {
    log.debug("Read entry " + entryName);
    
    // Creates file with same name as entry
    File file = new File(entryName);
    // Ensures we don't overwrite anything
    if (file.exists()) {
        throw new IllegalStateException("File already exists");
    }
    asicReader.writeFile(file);
    
    // Removes file immediately, since this is just a test 
    file.delete();  
}
asicReader.close(); 
```


## Security

This library validate signatures, but does not validate the certificate. It's up to the implementer using the library
to choose if and how to validate certificates. Certificate(s) used for validation is exposed by the library.


## Creating an ASiC-E container manually

This is how you create an ASiC container manually:

1. Create empty directory named `asic-sample`
1. Copy the files `bii-envelope.xml`and `bii-trns081.xml` into `asic-sample`
1. Create the directory `META-INF`:
1. Compute the SHA-256 digest value for the files and save them:
```
openssl dgst -sha256 -binary bii-envelope |base64
openssl dgst -sha256 -binary bii-message |base64

```
1. Create the file `META-INF/asicmanifest.xml`, add an entry for each file and
paste the SHA-256 values computed in the previous step. The file should look something like this:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ns2="http://www.w3.org/2000/09/xmldsig#">
  <SigReference URI="META-INF/signature.p7s" MimeType="application/x-pkcs7-signature"/>
  <DataObjectReference URI="bii-trns081.xml" MimeType="application/xml">
    <ns2:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ns2:DigestValue>morANIlh3TGxMUsJWKfICly7YXoduG7LCohAKc2Sip8=</ns2:DigestValue>
  </DataObjectReference>
  <DataObjectReference URI="bii-envelope.xml" MimeType="application/xml">
    <ns2:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ns2:DigestValue>IZ9yiwKHsTWMcyFebi7csqOOIHohy2gPd02VSfbyUCI=</ns2:DigestValue>
  </DataObjectReference>
</ASiCManifest>
```
1. Create the signature, which should be placed into `signature.p7s`. The file `comodo.pem` should
be replaced with the PEM-file holding your private key for the signature, and the certificate to prove it.
```
openssl cms -sign -in META-INF/asicmanifest.xml -binary -outform der -out META-INF/signature.p7s -signer comodo.pem
```

1. Verify the signature:
```
openssl cms -verify -in META-INF/signature.p7s -inform der -content META-INF/asicmanifest.xml -noverify
```
Note! The `-noverify` option omits verifying the certificate chain of trust and should only be used to verify that the files were created properly

1. Create the ZIP-archive using your favourite tool :-)

**Disclaimer:** The procedure liste above works on a Mac or Linux machine with the various tools pre-installed. If you are running on a windows machine
you need to download and install the *openssl* and *base64* tool and adapt the procedure according to your liking.


## Verifying the contents using *openssl*

Here is how to verify the signature using the *openssl(1)* command line tool:

```
openssl cms -verify -in META-INF/signature.p7s -inform der -content META-INF/asicmanifest.xml -noverify
```

The `-noverify` option will allow self signed certificates, and should normally be omitted :-).


## Programmers notes

You might encounter memory problems when using Java 1.7. This is due to the memory consumption of JAXB.

Try this before you run maven, you might need to increase this even further (your mileage may vary):
```
export MAVEN_OPTS="-Xmx1024m -XX:MaxPermSize=512m"
```
or on Windows:
```
set MAVEN_OPTS=-Xmx1024m -XX:MaxPermSize=512m
```

---

My personal [Coding Styleguide](https://github.com/phax/meta/blob/master/CodingStyleguide.md) |
It is appreciated if you star the GitHub project if you like it.