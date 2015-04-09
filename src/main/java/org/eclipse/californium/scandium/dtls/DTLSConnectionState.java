/*******************************************************************************
 * Copyright (c) 2014, 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - turn into an immutable, reduce visibility
 *                                                    to improve encapsulation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Represents the state of a DTLS connection.
 * 
 * It specifies a compression algorithm, an
 * encryption algorithm, and a MAC algorithm. For a connection, there are always
 * for connection states outstanding: the current read and write states, and the
 * pending read and write states. All records are processed under the current
 * read and write states. See <a
 * href="http://tools.ietf.org/html/rfc5246#section-6.1">RFC 5246</a> for
 * details.
 */
class DTLSConnectionState {
	
	// Members ////////////////////////////////////////////////////////

	private CipherSuite cipherSuite;
	private CompressionMethod compressionMethod;
	private SecretKey encryptionKey;
	private IvParameterSpec iv;
	private SecretKey macKey;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Convenience constructor for creating an instance representing
	 * the initial connection state.
	 * 
	 * Simply invokes 
	 * {@link #DTLSConnectionState(CipherSuite, CompressionMethod, SecretKey, IvParameterSpec, SecretKey)}
	 * with the default {@link CipherSuite#TLS_NULL_WITH_NULL_NULL} and default
	 * {@link CompressionMethod#NULL} and <code>null</code> for all other parameters.
	 */
	DTLSConnectionState() {
		this(CipherSuite.TLS_NULL_WITH_NULL_NULL, CompressionMethod.NULL, null, null, null);
	}

	/**
	 * Initializes all fields with given values.
	 * 
	 * @param cipherSuite
	 *            the cipher suite used
	 * @param compressionMethod
	 *            the compression used
	 * @param encryptionKey
	 *            the secret encryption key used
	 * @param iv
	 *            the initialization vector used
	 * @param macKey
	 *            the MAC key used
	 */
	DTLSConnectionState(CipherSuite cipherSuite, CompressionMethod compressionMethod, SecretKey encryptionKey, IvParameterSpec iv, SecretKey macKey) {
		this.cipherSuite = cipherSuite;
		this.compressionMethod = compressionMethod;
		this.encryptionKey = encryptionKey;
		this.iv = iv;
		this.macKey = macKey;
	}

	// Getters ////////////////////////////////////////////

	CipherSuite getCipherSuite() {
		return cipherSuite;
	}

	CompressionMethod getCompressionMethod() {
		return compressionMethod;
	}

	SecretKey getEncryptionKey() {
		return encryptionKey;
	}

	IvParameterSpec getIv() {
		return iv;
	}

	SecretKey getMacKey() {
		return macKey;
	}
}
