/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *     Achim Kraus (Bosch Software Innovations GmbH) - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;

/**
 * Connection id generator.
 * 
 * Responsible for generating ID which identifies scandium connections in store.
 * 
 * By default, DTLS defined that IP address and port of the peer are used to
 * identify the DTLS Connection. The DTLS connection ID draft defines a way to
 * identify connection using Connection ID and so supports environments where IP
 * address/port changes. See <a href=
 * "https://tools.ietf.org/html/draft-ietf-tls-dtls-connection-id-03">draft-ietf-tls-dtls-connection-id-03</a>.
 * 
 * The draft enables the peers to chose the level of support or usage. The dtls
 * client peer informs the dtls server peer about its preference using a new
 * HELLO_EXTENSION in it's CLIENT_HELLO.
 * <p>
 * The dtls client can chose:
 * <dl>
 * <dt>client doesn't support it</dt>
 * <dd>the new extension is not included in the client hello</dd>
 * <dt>client supports it (but doesn't use it)</dt>
 * <dd>the new extension with an empty connection id (0 length) is included in
 * the client hello</dd>
 * <dt>client uses it</dt>
 * <dd>the new extension with a non-empty connection id is included in the
 * client hello</dd>
 * </dl>
 * <p>
 * If the client doesn't support it, the server must reply with a server hello
 * without the new hello extension, regardless of the configuration.
 * <p>
 * If the client supports or uses it, the server can chose.
 * <dl>
 * <dt>server doesn't support it</dt>
 * <dd>the new extension is not included in the server hello</dd>
 * <dt>server supports it (but doesn't use it)</dt>
 * <dd>the new extension with an empty connection id (0 length) is included in
 * the server hello</dd>
 * <dt>server uses it</dt>
 * <dd>the new extension with a non-empty connection id is included in the
 * server hello</dd>
 * </dl>
 * <p>
 * The behavior of a peer within the above rules could be configured using
 * {@link DtlsConnectorConfig.Builder#setConnectionIdGenerator(ConnectionIdGenerator)}.
 * <dl>
 * <dt>do not support it</dt>
 * <dd>use a {@code null} as connection id generator</dd>
 * <dt>support it (but doesn't use it)</dt>
 * <dd>use a {@link ConnectionIdGenerator}, which returns {@code false} on
 * {@link #useConnectionId()}</dd>
 * <dt>use it</dt>
 * <dd>use a {@link ConnectionIdGenerator}, which returns {@code true} on
 * {@link #useConnectionId()} and generates and reads connection ids.</dd>
 * </dl>
 */
public interface ConnectionIdGenerator {

	/**
	 * Indicates, if connection ids are used or just supported.
	 * 
	 * @return {@code true}, if a connection is used, {@code false}, if only a
	 *         connection id from the other peer is supported.
	 */
	boolean useConnectionId();

	/**
	 * Creates a connection id.
	 * 
	 * The caller must take care to use only unique connection ids. In cases
	 * where the generated connection id is already in use, it's intended to
	 * create a next connection id calling this method again.
	 * 
	 * @return created connection id or {@code null}, if this generator only
	 *         supports connection ids from the other peer.
	 */
	ConnectionId createConnectionId();

	/**
	 * Read connection id from record header bytes.
	 * 
	 * @param reader reader with header bytes at the position of the connection
	 *            id.
	 * @return read connection id or {@code null}, if this generator only
	 *         supports connection ids from the other peer.
	 */
	ConnectionId read(DatagramReader reader);
}
