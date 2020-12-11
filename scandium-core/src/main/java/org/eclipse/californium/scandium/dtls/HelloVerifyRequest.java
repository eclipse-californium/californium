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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * The server send this request after receiving a {@link ClientHello} message to
 * prevent Denial-of-Service Attacks.
 * <p>
 * See <a href="https://tools.ietf.org/html/rfc6347#section-4.2.1">RFC 6347</a>
 * for the definition.
 * </p>
 * <p>
 * It seems, that this definition is ambiguous about the server version to be
 * used.
 * </p>
 * <pre>
 * The server_version field ...
 * DTLS 1.2 server implementations SHOULD use DTLS version 1.0 regardless
 * of the version of TLS that is expected to be negotiated. ...
 * The server MUST use the same version number in the HelloVerifyRequest
 * that it would use when sending a ServerHello. ...
 * </pre>
 * <p>
 * A DTLS 1.2 server can either (SHOULD) send a version 1.0, or (MUST use same
 * version) 1.2. This question is pending in the IETF TLS mailing list, see
 * <a href=
 * "https://mailarchive.ietf.org/arch/msg/tls/rQ3El3ROKTN0rpzhRpJCaKOrUyU/">RFC
 * 6347 - Section 4.2.1 - used version in a HelloVerifyReques</a>.
 * </p>
 * <p>
 * There may be many assumptions about the intended behavior. One is to postpone
 * the version negotiation according
 * <a href= "https://tools.ietf.org/html/rfc5246#appendix-E.1">RFC 5246 - E.1 -
 * Compatibility with TLS 1.0/1.1 and SSL 3.0</a> until the endpoint ownership is
 * verified. That prevents sending protocol-version alerts to wrong clients.
 * </p>
 * 
 * Behavior of other DTLS 1.2 implementations:
 * <dl>
 * <dt>openssl 1.1.1</dt>
 * <dd>1.0</dd>
 * <dt>gnutls 3.5.18</dt>
 * <dd>1.0</dd>
 * <dt>mbedtls 2.24.0</dt>
 * <dd>1.2</dd>
 * <dt>wolfssl 4.5</dt>
 * <dd>1.2</dd>
 * <dt>tinydtls 0.8.6</dt>
 * <dd>1.0 protocol-version in record-header, 1.2 server version in
 * hello-verify-request</dd>
 * </dl>
 * <p>
 * All clients of these libraries are able to perform a dtls-handshake with both
 * variants, 1.0 and 1.2. Some other clients seems to have trouble with 1.0. If
 * interoperability is required, a client MUST comply with the definition there:
 * </p>
 * 
 * <pre>
 * DTLS 1.2 and 1.0 clients MUST use the version solely to
 * indicate packet formatting (which is the same in both DTLS 1.2 and
 * 1.0) and not as part of version negotiation.  In particular, DTLS 1.2
 * clients MUST NOT assume that because the server uses version 1.0 in
 * the HelloVerifyRequest that the server is not DTLS 1.2 or that it
 * will eventually negotiate DTLS 1.0 rather than DTLS 1.2.
 * </pre>
 */
public final class HelloVerifyRequest extends HandshakeMessage {

	// DTLS-specific constants ///////////////////////////////////////////

	private static final int VERSION_BITS = 8; // for major and minor each

	private static final int COOKIE_LENGTH_BITS = 8;

	// Members ///////////////////////////////////////////////////////////

	/**
	 * This field will contain the lower of that suggested by the client in the
	 * client hello and the highest supported by the server.
	 */
	private final ProtocolVersion serverVersion;

	/** The cookie which needs to be replayed by the client. */
	private final byte[] cookie;

	// Constructor ////////////////////////////////////////////////////

	public HelloVerifyRequest(ProtocolVersion version, byte[] cookie) {
		this.serverVersion = version;
		this.cookie = cookie;
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter(cookie.length + 3);

		writer.write(serverVersion.getMajor(), VERSION_BITS);
		writer.write(serverVersion.getMinor(), VERSION_BITS);

		writer.writeVarBytes(cookie, COOKIE_LENGTH_BITS);

		return writer.toByteArray();
	}

	public static HandshakeMessage fromReader(DatagramReader reader) {

		int major = reader.read(VERSION_BITS);
		int minor = reader.read(VERSION_BITS);
		ProtocolVersion version = ProtocolVersion.valueOf(major, minor);

		byte[] cookie = reader.readVarBytes(COOKIE_LENGTH_BITS);

		return new HelloVerifyRequest(version, cookie);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.HELLO_VERIFY_REQUEST;
	}

	@Override
	public int getMessageLength() {
		// fixed: version (2) + cookie length (1)
		return 3 + cookie.length;
	}

	public ProtocolVersion getServerVersion() {
		return serverVersion;
	}

	public byte[] getCookie() {
		return cookie;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		sb.append("\t\tServer Version: ").append(serverVersion).append(StringUtil.lineSeparator());
		sb.append("\t\tCookie Length: ").append(cookie.length).append(StringUtil.lineSeparator());
		sb.append("\t\tCookie: ").append(StringUtil.byteArray2HexString(cookie)).append(StringUtil.lineSeparator());

		return sb.toString();
	}

}
