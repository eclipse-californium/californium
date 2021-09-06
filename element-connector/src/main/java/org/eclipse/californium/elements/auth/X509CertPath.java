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
import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.CertPathUtil;

/**
 * A path of X.509 certificates asserting the identity of a peer.
 * <p>
 * The path is an ordered list of X.509 certificates with the target (containing
 * the asserted identity) at first position and the certificate issued by the
 * trust anchor at the end of the list.
 */
public class X509CertPath extends AbstractExtensiblePrincipal<X509CertPath> {

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
	 * @throws NullPointerException if provided certificateChain is {@code null}
	 * @throws IllegalArgumentException if certificateChain is empty, or a
	 *             certificate is provided, which is no x509 certificate.
	 */
	public static X509CertPath fromCertificatesChain(Certificate... certificateChain) {
		if (certificateChain == null) {
			throw new NullPointerException("Certificate chain must not be null!");
		}
		if (certificateChain.length == 0) {
			throw new IllegalArgumentException("Certificate chain must not be empty!");
		}
		List<X509Certificate> chain = CertPathUtil.toX509CertificatesList(Arrays.asList(certificateChain));
		CertPath certPath = CertPathUtil.generateCertPath(chain);
		return new X509CertPath(certPath);
	}

	/**
	 * Create x509 certificate path from list of x509 certificates chain.
	 * 
	 * @param certificateChain chain of x509 certificates
	 * @return created x509 certificate path
	 * @throws NullPointerException if provided certificateChain is {@code null}
	 * @throws IllegalArgumentException if certificateChain is empty
	 */
	public static X509CertPath fromCertificatesChain(List<X509Certificate> certificateChain) {
		if (certificateChain == null) {
			throw new NullPointerException("Certificate chain must not be null!");
		}
		if (certificateChain.isEmpty()) {
			throw new IllegalArgumentException("Certificate chain must not be empty!");
		}
		CertPath certPath = CertPathUtil.generateCertPath(certificateChain);
		return new X509CertPath(certPath);
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
	 * Gets the subject DN of the asserted identity of this certificate path.
	 * 
	 * @return The subject.
	 */
	@Override
	public String getName() {
		return target.getSubjectX500Principal().getName();
	}

	/**
	 * Gets the CN of the subject DN.
	 * 
	 * @return CN, or {@code null}, if not available.
	 * @since 3.0
	 */
	public String getCN() {
		return CertPathUtil.getSubjectsCn(target);
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
