/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Represents a connection state. It specifies a compression algorithm, an
 * encryption algorithm, and a MAC algorithm. For a connection, there are always
 * for connection states outstanding: the current read and write states, and the
 * pending read and write states. All records are processed under the current
 * read and write states. See <a
 * href="http://tools.ietf.org/html/rfc5246#section-6.1">RFC 5246</a> for
 * details.
 */
public class DTLSConnectionState {
	
	// Members ////////////////////////////////////////////////////////

	private CipherSuite cipherSuite;
	private CompressionMethod compressionMethod;
	private SecretKey encryptionKey;
	private IvParameterSpec iv;
	private SecretKey macKey;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Constructor for the initial state.
	 */
	public DTLSConnectionState() {
		this.cipherSuite = CipherSuite.SSL_NULL_WITH_NULL_NULL;
		this.compressionMethod = CompressionMethod.NULL;
		this.encryptionKey = null;
		this.iv = null;
		this.macKey = null;
	}

	/**
	 * 
	 * @param cipherSuite
	 * @param compressionMethod
	 * @param encryptionKey
	 * @param iv
	 * @param macKey
	 */
	public DTLSConnectionState(CipherSuite cipherSuite, CompressionMethod compressionMethod, SecretKey encryptionKey, IvParameterSpec iv, SecretKey macKey) {
		this.cipherSuite = cipherSuite;
		this.compressionMethod = compressionMethod;
		this.encryptionKey = encryptionKey;
		this.iv = iv;
		this.macKey = macKey;
	}

	// Getters and Setters ////////////////////////////////////////////

	public CipherSuite getCipherSuite() {
		return cipherSuite;
	}

	public void setCipherSuite(CipherSuite cipherSuite) {
		this.cipherSuite = cipherSuite;
	}

	public CompressionMethod getCompressionMethod() {
		return compressionMethod;
	}

	public void setCompressionMethod(CompressionMethod compressionMethod) {
		this.compressionMethod = compressionMethod;
	}

	public SecretKey getEncryptionKey() {
		return encryptionKey;
	}

	public void setEncryptionKey(SecretKey encryptionKey) {
		this.encryptionKey = encryptionKey;
	}

	public IvParameterSpec getIv() {
		return iv;
	}

	public void setIv(IvParameterSpec iv) {
		this.iv = iv;
	}

	public SecretKey getMacKey() {
		return macKey;
	}

	public void setMacKey(SecretKey macKey) {
		this.macKey = macKey;
	}
}
