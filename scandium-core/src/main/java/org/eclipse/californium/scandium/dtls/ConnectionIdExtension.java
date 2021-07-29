/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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

/**
 * Conveys information specified by the <em>connection id</em> DTLS extension.
 * <p>
 * See <a href=
 * "https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id">draft-ietf-tls-dtls-connection-id</a>
 * for additional details.
 *
 * <b>Note:</b> Before version 9 of the specification, the value {@code 53} was
 * used as extension ID along with a different calculated MAC.
 * 
 * @see ExtensionType#CONNECTION_ID
 * @see ExtensionType#CONNECTION_ID_DEPRECATED
 */
public final class ConnectionIdExtension extends HelloExtension {

	/**
	 * Number of bits for the encoded length of the connection id in the
	 * extension.
	 */
	private static final int CID_FIELD_LENGTH_BITS = 8;

	/**
	 * Connection id to negotiate.
	 */
	private final ConnectionId id;

	/**
	 * Create connection id extension.
	 * 
	 * @param id connection id
	 * @param deprecatedCid {@code true}, if the deprecated extension ID
	 *            {@code 53} and the deprecated MAC is used, {@code false},
	 *            otherwise.
	 * @since 3.0 (added parameter deprecatedCid)
	 */
	private ConnectionIdExtension(ConnectionId id, boolean deprecatedCid) {
		super(deprecatedCid ? ExtensionType.CONNECTION_ID_DEPRECATED : ExtensionType.CONNECTION_ID);
		this.id = id;
	}

	/**
	 * Get connection id.
	 * 
	 * @return connection id
	 */
	public ConnectionId getConnectionId() {
		return id;
	}

	/**
	 * Usage of deprecated definitions.
	 * 
	 * @return {@code true}, if the deprecated extension ID {@code 53} along
	 *         with the deprecated MAC calculation is used, {@code false},
	 *         otherwise.
	 */
	public boolean useDeprecatedCid() {
		return getType() == ExtensionType.CONNECTION_ID_DEPRECATED;
	}

	@Override
	public int getLength() {
		// 2 bytes indicating extension type, 2 bytes overall length,
		// 1 byte cid length + cid
		return 2 + 2 + 1 + id.length();
	}

	@Override
	protected void addExtensionData(final DatagramWriter writer) {
		int length = id.length();
		writer.write(1 + length, LENGTH_BITS);
		writer.writeVarBytes(id, CID_FIELD_LENGTH_BITS);
	}

	/**
	 * Create connection id extension from connection id.
	 * 
	 * @param cid connection id
	 * @param deprecatedCid {@code true}, {@code true}, if the deprecated
	 *            extension ID {@code 53} along with the deprecated MAC
	 *            calculation is used, {@code false}, otherwise.
	 * @return created connection id extension
	 * @throws NullPointerException if cid is {@code null}
	 * @since 3.0 (added parameter deprecatedCid)
	 */
	public static ConnectionIdExtension fromConnectionId(ConnectionId cid, boolean deprecatedCid) {
		if (cid == null) {
			throw new NullPointerException("cid must not be null!");
		}
		return new ConnectionIdExtension(cid, deprecatedCid);
	}

	/**
	 * Create connection id extension from extensions data bytes.
	 * 
	 * @param extensionDataReader extension data bytes
	 * @param deprecatedCid {@code true}, if the deprecated extension ID
	 *            {@code 53} along with the deprecated MAC calculation is used,
	 *            {@code false}, otherwise.
	 * @return created connection id extension
	 * @throws NullPointerException if extensionData is {@code null}
	 * @throws HandshakeException if the extension data could not be decoded
	 * @since 3.0 (added parameter deprecatedCid)
	 */
	public static ConnectionIdExtension fromExtensionDataReader(DatagramReader extensionDataReader,
			boolean deprecatedCid) throws HandshakeException {
		if (extensionDataReader == null) {
			throw new NullPointerException("cid must not be null!");
		}
		int availableBytes = extensionDataReader.bitsLeft() / Byte.SIZE;
		if (availableBytes == 0) {
			throw new HandshakeException("Connection id length must be provided!",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
		} else if (availableBytes > 256) {
			throw new HandshakeException("Connection id length too large! 255 max, but has " + (availableBytes - 1),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
		}
		int len = extensionDataReader.read(CID_FIELD_LENGTH_BITS);
		if (len != (availableBytes - 1)) {
			throw new HandshakeException("Connection id length " + len + " doesn't match " + (availableBytes - 1) + "!",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
		}
		if (len == 0) {
			return new ConnectionIdExtension(ConnectionId.EMPTY, deprecatedCid);
		} else {
			byte[] cid = extensionDataReader.readBytes(len);
			return new ConnectionIdExtension(new ConnectionId(cid), deprecatedCid);
		}
	}

}
