package org.eclipse.californium.scandium.dtls.x509;

import java.security.cert.X509Certificate;

import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeException;

/**
 * A class in charge of verifying a X.509 certificate chain provided by a peer.
 * 
 * @see StaticCertificateVerifier
 */
public interface CertificateVerifier {

	/**
	 * Validates the X.509 certificate chain provided by the the peer as part of
	 * this message.
	 * 
	 * @param message certificate message to be verified
	 * @param session dtls session to verify
	 * @throws HandshakeException if verification fails
	 */
	void verifyCertificate(CertificateMessage message, DTLSSession session) throws HandshakeException;

	/**
	 * Return an array of certificate authority certificates which are trusted
	 * for authenticating peers.
	 * 
	 * @return the trusted CA certificates (possibly <code>null</code>)
	 */
	X509Certificate[] getAcceptedIssuers();

}
