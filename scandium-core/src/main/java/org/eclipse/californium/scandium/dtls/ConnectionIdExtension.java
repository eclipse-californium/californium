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
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;

/**
 * Conveys information specified by the <em>connection id</em> DTLS extension.
 * <p>
 * See
 * <a href= "https://www.rfc-editor.org/rfc/rfc9146.html" target ="_blank">RFC
 * 9146, Connection Identifier for DTLS 1.2</a> for additional details.
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
	 * @param type {@link ExtensionType#CONNECTION_ID}, or a type, with that as
	 *            {@link ExtensionType#getReplacementType()}.
	 * @since 3.0 (added parameter deprecatedCid)
	 */
	private ConnectionIdExtension(ConnectionId id, ExtensionType type) {
		super(type);
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
	 * During the specification of
	 * <a href= "https://www.rfc-editor.org/rfc/rfc9146.html" target
	 * ="_blank">RFC 9146, Connection Identifier for DTLS 1.2</a> a deprecated
	 * MAC calculation was used along with a also deprecated IANA code point
	 * (53) was used before version 09. To support the deprecated version as
	 * well, the return value indicates, which MAC variant must be used.
	 * 
	 * @return {@code true}, if not the current extension ID {@code 54} along
	 *         with the new MAC calculation is used, {@code false}, otherwise.
	 * @since 3.0
	 */
	public boolean useDeprecatedCid() {
		return getType() != ExtensionType.CONNECTION_ID;
	}

	@Override
	public String toString(int indent) {
		StringBuilder sb = new StringBuilder(super.toString(indent));
		String indentation = StringUtil.indentation(indent + 1);
		sb.append(indentation).append("DTLS Conection ID: ").append(id).append(StringUtil.lineSeparator());
		return sb.toString();
	}

	@Override
	protected int getExtensionLength() {
		// 1 byte cid length + cid
		return (CID_FIELD_LENGTH_BITS / Byte.SIZE) + id.length();
	}

	@Override
	protected void writeExtensionTo(DatagramWriter writer) {
		writer.writeVarBytes(id, CID_FIELD_LENGTH_BITS);
	}

	/**
	 * Create connection id extension from connection id.
	 * 
	 * @param cid connection id
	 * @param type extension type. Must be of type
	 *            {@link ExtensionType#CONNECTION_ID} or the
	 *            {@link ExtensionType#getReplacementType()} must be
	 *            {@link ExtensionType#CONNECTION_ID}.
	 * @return created connection id extension
	 * @throws NullPointerException if cid or type is {@code null}
	 * @throws IllegalArgumentException if type is not
	 *             {@link ExtensionType#CONNECTION_ID} and
	 *             {@link ExtensionType#getReplacementType()} is also not
	 *             {@link ExtensionType#CONNECTION_ID}.
	 * @since 3.0 (added parameter type to support deprecated cid code points
	 *        and MAC calculation)
	 */
	public static ConnectionIdExtension fromConnectionId(ConnectionId cid, ExtensionType type) {
		if (cid == null) {
			throw new NullPointerException("cid must not be null!");
		}
		if (type == null) {
			throw new NullPointerException("type must not be null!");
		}
		if (type != ExtensionType.CONNECTION_ID && type.getReplacementType() != ExtensionType.CONNECTION_ID) {
			throw new IllegalArgumentException(type + " type is not supported as Connection ID!");
		}
		return new ConnectionIdExtension(cid, type);
	}

	/**
	 * Create connection id extension from extensions data bytes.
	 * 
	 * @param extensionDataReader extension data bytes
	 * @param type extension type. Must be of type
	 *            {@link ExtensionType#CONNECTION_ID} or the
	 *            {@link ExtensionType#getReplacementType()} must be
	 *            {@link ExtensionType#CONNECTION_ID}.
	 * @return created connection id extension
	 * @throws NullPointerException if extensionData or type is {@code null}
	 * @throws IllegalArgumentException if type is not
	 *             {@link ExtensionType#CONNECTION_ID} and
	 *             {@link ExtensionType#getReplacementType()} is also not
	 *             {@link ExtensionType#CONNECTION_ID}.
	 * @throws HandshakeException if the extension data could not be decoded
	 * @since 3.0 (added parameter deprecatedCid)
	 */
	public static ConnectionIdExtension fromExtensionDataReader(DatagramReader extensionDataReader, ExtensionType type)
			throws HandshakeException {
		if (extensionDataReader == null) {
			throw new NullPointerException("cid must not be null!");
		}
		if (type == null) {
			throw new NullPointerException("type must not be null!");
		}
		if (type != ExtensionType.CONNECTION_ID && type.getReplacementType() != ExtensionType.CONNECTION_ID) {
			throw new IllegalArgumentException(type + " type is not supported as Connection ID!");
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
			return new ConnectionIdExtension(ConnectionId.EMPTY, type);
		} else {
			byte[] cid = extensionDataReader.readBytes(len);
			return new ConnectionIdExtension(new ConnectionId(cid), type);
		}
	}
}
