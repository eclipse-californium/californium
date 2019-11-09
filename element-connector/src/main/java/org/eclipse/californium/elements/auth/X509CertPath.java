/*******************************************************************************
 * Copyright (c) 2016 - 2019 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add "include root"
 ******************************************************************************/
package org.eclipse.californium.elements.auth;

import java.io.ByteArrayInputStream;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A path of X.509 certificates asserting the identity of a peer.
 * <p>
 * The path is an ordered list of X.509 certificates with the target (containing
 * the asserted identity) at first position and the certificate issued by the
 * trust anchor at the end of the list.
 */
public class X509CertPath extends AbstractExtensiblePrincipal<X509CertPath> {

	private static final Logger LOGGER = LoggerFactory.getLogger(X509CertPath.class.getCanonicalName());
	private static final String TYPE_X509 = "X.509";
	private static final String ENCODING = "PkiPath";
	private final CertPath path;
	private final X509Certificate target;

	/**
	 * Creates a new instance for a certificate chain.
	 * 
	 * @param certPath The certificate chain asserting the peer's identity.
	 * @throws IllegalArgumentException if the given certificate chain is empty
	 *             or does not contain X.509 certificates only.
	 */
	public X509CertPath(final CertPath certPath) {
		this(certPath, null);
	}

	/**
	 * Creates a new instance for a certificate chain.
	 * 
	 * @param certPath The certificate chain asserting the peer's identity.
	 * @param additionalInformation Additional information for this principal.
	 * @throws IllegalArgumentException if the given certificate chain is empty
	 *             or does not contain X.509 certificates only.
	 */
	private X509CertPath(final CertPath certPath, AdditionalInfo additionalInformation) {
		super(additionalInformation);
		if (!TYPE_X509.equals(certPath.getType())) {
			throw new IllegalArgumentException("Cert path must contain X.509 certificates only");
		} else if (certPath.getCertificates().isEmpty()) {
			throw new IllegalArgumentException("Cert path must not be empty");
		} else {
			this.path = certPath;
			this.target = (X509Certificate) certPath.getCertificates().get(0);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509CertPath amend(AdditionalInfo additionInfo) {
		return new X509CertPath(path, additionInfo);
	}

	/**
	 * Creates a new instance from a <em>PkiPath</em> encoded certificate chain.
	 * 
	 * @param encodedPath The encoded chain.
	 * @return The certificate chain.
	 * @throws IllegalArgumentException if the given byte array does cannot be
	 *             parsed into an X.509 certificate chain.
	 */
	public static X509CertPath fromBytes(final byte[] encodedPath) {

		try {
			CertificateFactory factory = CertificateFactory.getInstance(TYPE_X509);
			CertPath certPath = factory.generateCertPath(new ByteArrayInputStream(encodedPath), ENCODING);
			return new X509CertPath(certPath);
		} catch (CertificateException e) {
			throw new IllegalArgumentException("byte array does not contain X.509 certificate path");
		}
	}

	/**
	 * Create x509 certificate path from array certificates chain.
	 * 
	 * @param certificateChain chain of certificates
	 * @return created x509 certificate path
	 */
	public static X509CertPath fromCertificatesChain(Certificate... certificateChain) {
		if (certificateChain != null && certificateChain.length == 0) {
			throw new IllegalArgumentException("Certificate chain must not be empty!");
		}
		List<X509Certificate> chain = new ArrayList<>();
		for (Certificate cert : certificateChain) {
			if (!(cert instanceof X509Certificate)) {
				throw new IllegalArgumentException("Given certificate is not X.509! " + cert);
			}
			chain.add((X509Certificate)cert);
		}
		CertPath certPath = generateCertPath(true, chain);
		return new X509CertPath(certPath);
	}

	/**
	 * Create x509 certificate path from list of x509 certificates chain.
	 * 
	 * @param certificateChain chain of x509 certificates
	 * @return created x509 certificate path
	 */
	public static X509CertPath fromCertificatesChain(List<X509Certificate>  certificateChain) {
		if (certificateChain != null && certificateChain.isEmpty()) {
			throw new IllegalArgumentException("Certificate chain must not be empty!");
		}
		CertPath certPath = generateCertPath(true, certificateChain);
		return new X509CertPath(certPath);
	}

	/**
	 * Create certificate path from x509 certificates chain.
	 * 
	 * @param includeRoot {@code true}, to include the root certificate in the
	 *            path, {@code false} otherwise.
	 * @param certificateChain list with chain of x509 certificates
	 * @return created certificate path
	 */
	public static CertPath generateCertPath(boolean includeRoot, List<X509Certificate> certificateChain) {
		if (certificateChain == null) {
			throw new NullPointerException("Certificate chain must not be null!");
		}
		List<X509Certificate> certificates = new ArrayList<>();
		X500Principal issuer = null;
		try {
			int index = 0;
			CertificateFactory factory = CertificateFactory.getInstance(TYPE_X509);
			for (Certificate cert : certificateChain) {
				if (!(cert instanceof X509Certificate)) {
					throw new IllegalArgumentException("Given certificate is not X.509! " + cert);
				}
				X509Certificate xcert = (X509Certificate) cert;
				LOGGER.debug("Current Subject DN: {}", xcert.getSubjectX500Principal().getName());
				if (issuer != null && !issuer.equals(xcert.getSubjectX500Principal())) {
					LOGGER.debug("Actual Issuer DN: {}", xcert.getSubjectX500Principal().getName());
					throw new IllegalArgumentException("Given certificates do not form a chain");
				}
				++index;
				if (xcert.getIssuerX500Principal().equals(xcert.getSubjectX500Principal())) {
					// a self-signed root certificate
					if (index != certificateChain.size()) {
						throw new IllegalArgumentException(
								"Given certificates do not form a chain, root is not the last!");
					}
					if (includeRoot || certificateChain.size() == 1) {
						certificates.add(xcert);
					}
				} else {
					// not a self-signed certificate
					certificates.add(xcert);
					issuer = xcert.getIssuerX500Principal();
					LOGGER.debug("Expected Issuer DN: {}", issuer.getName());
				}
			}
			return factory.generateCertPath(certificates);
		} catch (CertificateException e) {
			// should not happen because all Java 7 implementation MUST
			// support
			// X.509 certificates
			throw new IllegalArgumentException("could not create X.509 certificate factory", e);
		}
	}

	/**
	 * Gets a binary representation of this certificate chain using the
	 * <em>PkiPath</em> encoding.
	 * 
	 * @return The binary encoding.
	 */
	public byte[] toByteArray() {
		try {
			return path.getEncoded(ENCODING);
		} catch (CertificateEncodingException e) {
			// should not happen because all Java 7 implementations are required
			// to support PkiPath encoding of X.509 certificates
			return Bytes.EMPTY;
		}
	}

	/**
	 * Gets the Subject DN of the asserted identity of this certificate path.
	 * 
	 * @return The subject.
	 */
	@Override
	public String getName() {
		return target.getSubjectX500Principal().getName();
	}

	/**
	 * Gets this certificate path.
	 *
	 * @return The path.
	 */
	public CertPath getPath() {
		return path;
	}

	/**
	 * Gets the asserted identity of this certificate path.
	 *
	 * @return The target certificate.
	 */
	public X509Certificate getTarget() {
		return target;
	}

	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj == null) {
			return false;
		} else if (getClass() != obj.getClass()) {
			return false;
		}
		X509CertPath other = (X509CertPath) obj;
		return this.target.equals(other.target);
	}

	public int hashCode() {
		return target.hashCode();
	}

	/**
	 * Gets a string representation of this principal.
	 * 
	 * Clients should not assume any particular format of the returned string
	 * since it may change over time.
	 *  
	 * @return the string representation
	 */
	@Override
	public String toString() {
		return new StringBuilder("x509 [").append(getName()).append("]").toString();
	}

}
