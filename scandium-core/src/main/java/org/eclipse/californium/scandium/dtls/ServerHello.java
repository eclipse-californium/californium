/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fixes & additions
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessors for certificate types
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * A TLS handshake message sent by a server in response to a {@link ClientHello}
 * message received from a client.
 * 
 * The server will send this message in response to a {@link ClientHello}
 * message when it was able to find an acceptable set of algorithms. If it
 * cannot find such a match, it will respond with a handshake failure alert. See
 * <a href="https://tools.ietf.org/html/rfc5246#section-7.4.1.3" target=
 * "_blank">RFC 5246</a> for further details.
 */
public final class ServerHello extends HelloHandshakeMessage {

	/**
	 * The single {@link CipherSuite} selected by the server from the list in
	 * {@link ClientHello}.cipher_suites.
	 */
	private final CipherSuite cipherSuite;

	/**
	 * The single compression algorithm selected by the server from the list in
	 * ClientHello.compression_methods.
	 */
	private final CompressionMethod compressionMethod;

	/**
	 * Constructs a full <em>ServerHello</em> message. See
	 * <a href="https://tools.ietf.org/html/rfc5246#section-7.4.1.3" target=
	 * "_blank"> RFC 5246 (TLS 1.2), Section 7.4.1.3. Server Hello</a> for
	 * details.
	 * 
	 * @param version the negotiated version (highest supported by server).
	 * @param sessionId the new session's identifier.
	 * @param cipherSuite the negotiated cipher suite.
	 * @param compressionMethod the negotiated compression method.
	 * @throws NullPointerException if any of the parameters is {@code null}
	 * @since 3.0 (removed parameter random)
	 */
	public ServerHello(ProtocolVersion version, SessionId sessionId, CipherSuite cipherSuite,
			CompressionMethod compressionMethod) {
		super(version, sessionId);
		if (cipherSuite == null) {
			throw new NullPointerException("Negotiated cipher suite must not be null");
		}
		if (compressionMethod == null) {
			throw new NullPointerException("Negotiated compression method must not be null");
		}
		this.cipherSuite = cipherSuite;
		this.compressionMethod = compressionMethod;
	}

	private ServerHello(DatagramReader reader) throws HandshakeException {
		super(reader);

		int code = reader.read(CipherSuite.CIPHER_SUITE_BITS);
		cipherSuite = CipherSuite.getTypeByCode(code);
		if (cipherSuite == null) {
			throw new HandshakeException(
					String.format("Server selected unknown cipher suite [%s]", Integer.toHexString(code)),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
		} else if (!cipherSuite.isValidForNegotiation()) {
			throw new HandshakeException("Server tries to negotiate a cipher suite invalid for negotiation",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
		}
		compressionMethod = CompressionMethod.getMethodByCode(reader.read(CompressionMethod.COMPRESSION_METHOD_BITS));

		extensions.readFrom(reader);
	}

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();
		writeHeader(writer);

		writer.write(cipherSuite.getCode(), CipherSuite.CIPHER_SUITE_BITS);
		writer.write(compressionMethod.getCode(), CompressionMethod.COMPRESSION_METHOD_BITS);

		extensions.writeTo(writer);

		return writer.toByteArray();
	}

	/**
	 * Creates a <em>Server Hello</em> object from its binary encoding as used
	 * on the wire.
	 * 
	 * @param reader reader for the binary encoding of the message.
	 * @return the object representation
	 * @throws HandshakeException if the cipher suite code selected by the
	 *             server is either unknown, i.e. not defined in
	 *             {@link CipherSuite} at all, or not 
	 *             {@link CipherSuite#isValidForNegotiation()}
	 */
	public static HandshakeMessage fromReader(DatagramReader reader) throws HandshakeException {
		return new ServerHello(reader);
	}

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.SERVER_HELLO;
	}

	@Override
	public int getMessageLength() {
		/*
		 * fixed sizes: version (2) + random (32) + session ID length (1) +
		 * cipher suite (2) + compression method (1) = 38
		 * variable sizes: session ID, extensions
		 */
		return 38 + sessionId.length() + extensions.getLength();
	}

	/**
	 * Gets the cipher suite the server has chosen for the session being
	 * negotiated.
	 * 
	 * @return The cipher suite.
	 */
	public CipherSuite getCipherSuite() {
		return cipherSuite;
	}

	/**
	 * Gets the compression method the server has chosen for the session being
	 * negotiated.
	 * 
	 * @return The compression method.
	 */
	public CompressionMethod getCompressionMethod() {
		return compressionMethod;
	}

	@Override
	public String toString(int indent) {
		StringBuilder sb = new StringBuilder(super.toString(indent));
		String indentation = StringUtil.indentation(indent + 1);
		sb.append(indentation).append("Cipher Suite: ").append(cipherSuite).append(StringUtil.lineSeparator());
		sb.append(indentation).append("Compression Method: ").append(compressionMethod).append(StringUtil.lineSeparator());
		sb.append(extensions.toString(indent + 1));

		return sb.toString();
	}

}
