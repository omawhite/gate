package com.netflix.spinnaker.gate.security.x509

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OctetString

import java.security.cert.X509Certificate

class OidRolesExtractor implements X509RolesExtractor {
  private String oid

  @Override
  Collection<String> fromCertificate(X509Certificate cert) {
    byte[] bytes = cert.getExtensionValue(oid)

    if (bytes == null) {
      return []
    }
    ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes))
    ASN1OctetString octs = (ASN1OctetString) aIn.readObject()
    aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()))
    return aIn.readObject().toString().split("\\n")
  }
}
