package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.scandium.dtls.CertificateTypeExtension.CertificateType;
import org.junit.Assert;
import org.junit.Test;

public class HelloExtensionsTest {

	@Test
	public void testSerializationDeserialization() throws HandshakeException {
		ClientCertificateTypeExtension ext = new ClientCertificateTypeExtension(true);
		ext.addCertificateType(CertificateType.X_509);
		ext.addCertificateType(CertificateType.RAW_PUBLIC_KEY);
		
		HelloExtensions extensions = new HelloExtensions();
		extensions.addExtension(ext);
		byte[] serializedExtension = extensions.toByteArray();
		
		HelloExtensions deserializedExt = HelloExtensions.fromByteArray(serializedExtension);
		ClientCertificateTypeExtension certTypeExt = (ClientCertificateTypeExtension)
				deserializedExt.getExtensions().get(0);
		Assert.assertTrue(certTypeExt.getCertificateTypes().size() == 2);
		
	}

}
