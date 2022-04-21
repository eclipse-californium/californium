/*******************************************************************************
 * Copyright (c) 2022 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.net.DatagramPacket;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.ProtocolVersion;
import org.eclipse.californium.scandium.dtls.Record;

/**
 * Filter valid DTLS incoming datagrams.
 * 
 * Use an advanced MAC error filter.
 * 
 * @since 3.5
 */
public class DtlsDatagramFilter implements DatagramFilter {

	/**
	 * Quiet time to reset the MAC error filter in nanoseconds.
	 * 
	 * @since 3.6
	 */
	private final long macErrorFilterQuietTimeNanos;
	/**
	 * Quiet time to reset the MAC error filter in nanoseconds.
	 * 
	 * @since 3.6
	 */
	private final int macErrorFilterThreshold;

	/**
	 * Create dtls datagram filter without MAC error filter.
	 */
	public DtlsDatagramFilter() {
		this.macErrorFilterQuietTimeNanos = 0;
		this.macErrorFilterThreshold = 0;
	}

	/**
	 * Create dtls datagram filter with MAC error filter, if configured.
	 * 
	 * @param config configuration for the MAC error filter.
	 * @since 3.6
	 */
	public DtlsDatagramFilter(Configuration config) {
		this.macErrorFilterQuietTimeNanos = config.get(DtlsConfig.DTLS_MAC_ERROR_FILTER_QUIET_TIME,
				TimeUnit.NANOSECONDS);
		this.macErrorFilterThreshold = config.get(DtlsConfig.DTLS_MAC_ERROR_FILTER_THRESHOLD);
		if (macErrorFilterQuietTimeNanos == 0 ^ macErrorFilterThreshold == 0) {
			throw new IllegalArgumentException(
					"DTLS MAC error filter configuration ambig! Use 0 for both, or larger than 0 for both!");
		}
	}

	@Override
	public boolean onReceiving(DatagramPacket packet) {
		if (packet.getLength() < Record.RECORD_HEADER_BYTES) {
			// drop, too short
			return false;
		}
		byte[] data = packet.getData();
		int offset = packet.getOffset();
		ContentType contentType = ContentType.getTypeByValue(data[offset]);
		if (contentType == null) {
			// drop
			return false;
		}
		if (data[offset + 3] != 0 || (data[offset + 4] & 0xff) > 1 || data[offset + 5] != 0) {
			// drop epoch > 1, seqn >= 0x0100000000
			return false;
		}
		if (contentType == ContentType.HANDSHAKE || contentType == ContentType.ALERT) {
			return true;
		}
		int major = 0xff & data[offset + 1];
		int minor = 0xff & data[offset + 2];
		if (major == ProtocolVersion.MAJOR_1 && minor == ProtocolVersion.MINOR_2) {
			return true;
		}
		// drop
		return false;
	}

	@Override
	public boolean onReceiving(Record record, Connection connection) {
		if (macErrorFilterThreshold > 0) {
			Object filterData = connection.getFilterData();
			if (filterData instanceof MacErrorFilter) {
				return !((MacErrorFilter) filterData).dropRecords(macErrorFilterThreshold, record.getReceiveNanos(),
						macErrorFilterQuietTimeNanos);
			}
		}
		return true;
	}

	@Override
	public boolean onMacError(Record record, Connection connection) {
		if (macErrorFilterThreshold > 0) {
			Object filterData = connection.getFilterData();
			if (filterData == null) {
				filterData = new MacErrorFilter(record.getReceiveNanos());
				connection.setFilterData(filterData);
			}
			if (filterData instanceof MacErrorFilter) {
				((MacErrorFilter) filterData).incrementMacErrors(record.getReceiveNanos(),
						macErrorFilterQuietTimeNanos);
			}
		}
		return false;
	}

	/**
	 * MAC error filter data per {@link Connection}.
	 * 
	 * @see Connection#getFilterData()
	 * @since 3.6
	 */
	private static class MacErrorFilter {

		/**
		 * MAC errors of current period.
		 */
		private long currentMacErrors = 0;
		/**
		 * Nano-timestamp of last MAC error.
		 */
		private long lastMacErrorsNanoTimestamp = 0;

		/**
		 * Create MAC error filter data.
		 * 
		 * @param now current nano-uptime
		 * @see Record#getReceiveNanos()
		 */
		private MacErrorFilter(long now) {
			lastMacErrorsNanoTimestamp = now;
		}

		/**
		 * Increment the number of MAC errors.
		 * 
		 * @param now current nano-uptime
		 * @param quietTimeNanos quiet time in nanoseconds
		 * @see Record#getReceiveNanos()
		 */
		private void incrementMacErrors(long now, long quietTimeNanos) {
			resetMacErrorFilter(now, quietTimeNanos);
			++currentMacErrors;
		}

		/**
		 * Check, if record is to be dropped by the filter.
		 * 
		 * @param macErrorThreshold threshold for MAC errors to activate the
		 *            filter
		 * @param now current nano-uptime
		 * @param quietTimeNanos quiet time in nanoseconds
		 * @return {@code true}, to drop the current record, {@code false} to
		 *         process it.
		 * @see Record#getReceiveNanos()
		 */
		private boolean dropRecords(int macErrorThreshold, long now, long quietTimeNanos) {
			resetMacErrorFilter(now, quietTimeNanos);
			return currentMacErrors > macErrorThreshold;
		}

		private void resetMacErrorFilter(long now, long quietTimeNanos) {
			if ((now - lastMacErrorsNanoTimestamp) > quietTimeNanos) {
				currentMacErrors = 0;
			}
			lastMacErrorsNanoTimestamp = now;
		}

	}
}
