/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;

/**
 * Record size limit extension.
 * <p>
 * See <a href="http://tools.ietf.org/html/rfc8449">RFC 8449</a> for additional
 * details.
 * 
 * @since 2.4
 */
public final class RecordSizeLimitExtension extends HelloExtension {

	/**
	 * Minimum value for record size limit.
	 */
	public static final int MIN_RECORD_SIZE_LIMIT = 64;
	/**
	 * Maximum value for record size limit.
	 */
	public static final int MAX_RECORD_SIZE_LIMIT = 65535;

	/**
	 * Number of bits for the encoded record size limit in the extension.
	 */
	private static final int RECORD_SIZE_LIMIT_BITS = 16;

	/**
	 * Record size limit to negotiate.
	 */
	private int recordSizeLimit;

	/**
	 * Create record size limit extension.
	 * 
	 * @param recordSizeLimit record size limit
	 */
	public RecordSizeLimitExtension(int recordSizeLimit) {
		super(ExtensionType.RECORD_SIZE_LIMIT);
		this.recordSizeLimit = ensureInRange(recordSizeLimit);
	}

	/**
	 * Get record size limit.
	 * 
	 * @return record size limit
	 */
	public int getRecordSizeLimit() {
		return recordSizeLimit;
	}

	@Override
	public int getLength() {
		// 2 bytes indicating extension type,
		// 2 bytes overall length,
		// 2 bytes record size limit
		return (TYPE_BITS + LENGTH_BITS + RECORD_SIZE_LIMIT_BITS) / Byte.SIZE;
	}

	@Override
	protected void addExtensionData(final DatagramWriter writer) {
		writer.write(RECORD_SIZE_LIMIT_BITS / Byte.SIZE, LENGTH_BITS);
		writer.write(recordSizeLimit, RECORD_SIZE_LIMIT_BITS);
	}

	/**
	 * Create record size limit extension from extensions data bytes.
	 * 
	 * @param extensionDataReader extension data bytes
	 * @param peerAddress peer address
	 * @return created record size limit extension
	 * @throws NullPointerException if extensionData is {@code null}
	 * @throws HandshakeException if the extension data could not be decoded
	 */
	public static RecordSizeLimitExtension fromExtensionDataReader(DatagramReader extensionDataReader,
			final InetSocketAddress peerAddress) throws HandshakeException {
		if (extensionDataReader == null) {
			throw new NullPointerException("record size limit must not be null!");
		}
		int recordSizeLimit = extensionDataReader.read(RECORD_SIZE_LIMIT_BITS);
		if (recordSizeLimit < MIN_RECORD_SIZE_LIMIT) {
			throw new HandshakeException("record size limit must be at last " + MIN_RECORD_SIZE_LIMIT
					+ " bytes, not only " + recordSizeLimit + "!",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER, peerAddress));
		}
		return new RecordSizeLimitExtension(recordSizeLimit);
	}

	/**
	 * Ensure, that provided record limit is between
	 * {@link #MIN_RECORD_SIZE_LIMIT} and {@link #MAX_RECORD_SIZE_LIMIT}.
	 * 
	 * @param recordSizeLimit record size limit to ensure, that the value is in
	 *            range.
	 * @return {@link RecordSizeLimitExtension} the provided value, if in range
	 * @throws IllegalArgumentException if value is not in range
	 */
	public static int ensureInRange(int recordSizeLimit) {
		if (recordSizeLimit < MIN_RECORD_SIZE_LIMIT || recordSizeLimit > MAX_RECORD_SIZE_LIMIT) {
			throw new IllegalArgumentException("Record size limit must be within [" + MIN_RECORD_SIZE_LIMIT + "..."
					+ MAX_RECORD_SIZE_LIMIT + "], not " + recordSizeLimit + "!");
		}
		return recordSizeLimit;
	}
}
