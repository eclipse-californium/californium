/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.util.ServerName;
import org.eclipse.californium.scandium.util.ServerName.NameType;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Conveys information specified by the <em>Server Name Indication</em> TLS extension.
 * <p>
 * See <a href="https://tools.ietf.org/html/rfc6066#section-3">RFC 6066, Section 3</a> for additional details.
 *
 */
public final class ServerNameExtension extends HelloExtension {

	private static final int LIST_LENGTH_BITS = 16;

	private ServerNames serverNames;

	private ServerNameExtension() {
		super(ExtensionType.SERVER_NAME);
	}

	/**
	 * Creates a new instance for a server name list.
	 * <p>
	 * This constructor should be used by a client who wants to include the <em>Server Name Indication</em>
	 * extension in its <em>CLIENT_HELLO</em> handshake message.
	 * 
	 * @param serverNames The server names.
	 * @throws NullPointerException if the server name list is {@code null}.
	 */
	private ServerNameExtension(final ServerNames serverNames) {
		this();
		if (serverNames == null) {
			throw new NullPointerException("server names must not be null");
		}
		this.serverNames = serverNames;
	}

	/**
	 * Creates a new empty Server Name Indication extension.
	 * <p>
	 * This method should be used by a server that wants to include an empty <em>Server Name Indication</em>
	 * extension in its <em>SERVER_HELLO</em> handshake message.
	 * 
	 * @return The new instance.
	 */
	public static ServerNameExtension emptyServerNameIndication() {
		return new ServerNameExtension();
	}

	/**
	 * Creates a new instance for a single server's host name.
	 * <p>
	 * This method should be used by a client that wants to include the <em>Server Name Indication</em>
	 * extension in its <em>CLIENT_HELLO</em> handshake message.
	 * 
	 * @param hostName The host name of the server. NB: The host name MUST only contain ASCII characters,
	 *                 non-ASCII characters will be replaced by {@code StandardCharsets.US_ASCII}'s default
	 *                 replacement byte.
	 * @return The new instance.
	 * @throws NullPointerException if the host name is {@code null}.
	 */
	public static ServerNameExtension forHostName(final String hostName) {
		return new ServerNameExtension(ServerNames.newInstance(ServerName.from(NameType.HOST_NAME, hostName.getBytes(StandardCharsets.US_ASCII))));
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
		return new ServerNameExtension(serverNames);
	}

	@Override
	protected void addExtensionData(final DatagramWriter writer) {

		if (serverNames == null) {
			writer.write(0, LENGTH_BITS);
		} else {
			writer.write(serverNames.getEncodedLength() + 2, LENGTH_BITS); //extension_length
			writer.write(serverNames.getEncodedLength(), LIST_LENGTH_BITS); //server_names_list_length

			for (ServerName serverName : serverNames) {
				writer.writeByte(serverName.getType().getCode()); // name type
				writer.write(serverName.getName().length, LENGTH_BITS); // name length
				writer.writeBytes(serverName.getName()); // name
			}
		}
	}

	/**
	 * Creates a new instance from its byte representation.
	 * 
	 * @param extensionData The byte representation.
	 * @param peerAddress The IP address and port that the extension has been received from.
	 * @return The instance.
	 * @throws HandshakeException if the byte representation could not be parsed.
	 */
	public static ServerNameExtension fromExtensionData(final byte[] extensionData, final InetSocketAddress peerAddress) throws HandshakeException {
		if (extensionData == null || extensionData.length == 0) {
			// this is an "empty" Server Name Indication received in a SERVER_HELLO
			return ServerNameExtension.emptyServerNameIndication();
		} else {
			DatagramReader reader = new DatagramReader(extensionData);
			return readServerNameList(reader, peerAddress);
		}
	}

	private static ServerNameExtension readServerNameList(
			final DatagramReader reader,
			final InetSocketAddress peerAddress) throws HandshakeException {

		ServerNames serverNames = ServerNames.newInstance();
		int listLengthBytes = reader.read(LIST_LENGTH_BITS);
		while (listLengthBytes > 0) {
			if (reader.bitsLeft() >= 8) {
				NameType nameType = NameType.fromCode(reader.readNextByte());
				switch (nameType) {
				case HOST_NAME:
					byte[] hostname = readHostName(reader, peerAddress);
					serverNames.add(ServerName.from(nameType, hostname));
					listLengthBytes -= (hostname.length + 3);
					break;
				default:
					throw new HandshakeException(
							"Server Name Indication extension contains unknown name_type",
							new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER, peerAddress));
				}
			} else {
				throw newDecodeError(peerAddress);
			}
		}
		return new ServerNameExtension(serverNames);
	}

	private static byte[] readHostName(final DatagramReader reader, final InetSocketAddress peerAddress) throws HandshakeException {

		if (reader.bitsLeft() >= LENGTH_BITS) {
			int length = reader.read(LENGTH_BITS);
			if (reader.bytesAvailable(length)) {
				return reader.readBytes(length);
			}
		}
		throw newDecodeError(peerAddress);
	}

	private static HandshakeException newDecodeError(final InetSocketAddress peerAddress) {

		return new HandshakeException(
				"malformed Server Name Indication extension",
				new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR, peerAddress));
	}

	/**
	 * Gets the server name list conveyed in this extension.
	 * 
	 * @return The server names.
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
