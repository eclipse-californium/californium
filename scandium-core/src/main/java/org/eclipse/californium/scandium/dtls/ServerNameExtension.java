/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Conveys information specified by the <em>Server Name Indication</em> TLS extension.
 * <p>
 * See <a href="https://tools.ietf.org/html/rfc6066#section-3">RFC 6066, Section 3</a> for additional details.
 *
 */
public final class ServerNameExtension extends HelloExtension {
	
	private static ServerNameExtension EMPTY_SERVER_NAMES = new ServerNameExtension(null);

	private final ServerNames serverNames;

	/**
	 * Creates a new instance for a server name list.
	 * <p>
	 * This constructor should be used by a client who wants to include the <em>Server Name Indication</em>
	 * extension in its <em>CLIENT_HELLO</em> handshake message.
	 * 
	 * @param serverNames The server names. May be {@code null}.
	 */
	private ServerNameExtension(final ServerNames serverNames) {
		super(ExtensionType.SERVER_NAME);
		this.serverNames = serverNames;
	}

	/**
	 * Creates a new empty Server Name Indication extension.
	 * <p>
	 * This method should be used by a server that wants to include an empty <em>Server Name Indication</em>
	 * extension in its <em>SERVER_HELLO</em> handshake message.
	 * 
	 * @return The empty instance.
	 */
	public static ServerNameExtension emptyServerNameIndication() {
		return EMPTY_SERVER_NAMES;
	}

	/**
	 * Creates a new instance for a server name list.
	 * <p>
	 * This constructor should be used by a client who wants to include the <em>Server Name Indication</em>
	 * extension in its <em>CLIENT_HELLO</em> handshake message.
	 * 
	 * @param serverNames The server names.
	 * @return The new instance.
	 * @throws NullPointerException if the server name list is {@code null}.
	 */
	public static ServerNameExtension forServerNames(final ServerNames serverNames) {
		if (serverNames == null) {
			throw new NullPointerException("server names must not be null");
		}
		return new ServerNameExtension(serverNames);
	}

	@Override
	public void addExtensionData(final DatagramWriter writer) {

		if (serverNames == null) {
			writer.write(0, LENGTH_BITS);
		} else {
			writer.write(serverNames.getEncodedLength() + 2, LENGTH_BITS); //extension_length
			serverNames.encode(writer);
		}
	}

	/**
	 * Creates a new instance from its byte representation.
	 * 
	 * @param extensionDataReader The byte representation.
	 * @return The instance.
	 * @throws HandshakeException if the byte representation could not be parsed.
	 */
	public static ServerNameExtension fromExtensionDataReader(DatagramReader extensionDataReader) throws HandshakeException {
		if (!extensionDataReader.bytesAvailable()) {
			// this is an "empty" Server Name Indication received in a SERVER_HELLO
			return emptyServerNameIndication();
		} else {
			ServerNames serverNames = ServerNames.newInstance();
			try {
				serverNames.decode(extensionDataReader);
			} catch (IllegalArgumentException e) {
				if (e.getCause() instanceof IllegalArgumentException) {
					throw new HandshakeException("Server Name Indication extension contains unknown name_type",
							new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
				}
				throw new HandshakeException("malformed Server Name Indication extension",
						new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
			}
			return new ServerNameExtension(serverNames);
		}
	}

	/**
	 * Gets the server name list conveyed in this extension.
	 * 
	 * @return The server names. May be {@code null}.
	 */
	public ServerNames getServerNames() {
		return serverNames;
	}

	@Override
	public int getLength() {
		int length = 2; // 2 bytes indicating extension type
		length += 2; // overall extension length
		if (serverNames != null) {
			length += 2; // server_name_list_length
			length += serverNames.getEncodedLength();
		}
		return length;
	}

}
