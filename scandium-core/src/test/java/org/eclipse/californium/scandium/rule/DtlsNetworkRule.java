/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.rule;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.logging.Logger;

import org.eclipse.californium.elements.rule.NetworkRule;
import org.eclipse.californium.elements.util.DatagramFormatter;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.HandshakeType;
import org.eclipse.californium.scandium.dtls.Record;

/**
 * DTLS network rules for junit test using datagram sockets.
 *
 * The rule is intended to be mainly used as <code>&#64;ClassRule<code>
 * 
 * <pre>
 * public class AbcNetworkTest {
 *    &#64;ClassRule
 *    public static DtlsNetworkRule network = new DtlsNetworkRule(Mode.DIRECT, Mode.NATIVE);
 *    ...
 * </pre>
 * 
 * For the DIRECT mode there is an additional parameters available
 * {@link #setDelay(int)}.
 */
public class DtlsNetworkRule extends NetworkRule {

	public static final Logger LOGGER = Logger.getLogger(DtlsNetworkRule.class.getName());

	private static final InetSocketAddress ADDRESS = new InetSocketAddress(0) {

		private static final long serialVersionUID = 3463123750760014012L;

		@Override
		public String toString() {
			return "";
		}
	};

	/**
	 * CoAP datagram formatter. Used for logging.
	 */
	private static final DatagramFormatter FORMATTER = new DatagramFormatter() {
	
		@Override
		public String format(byte[] data) {
			if (null == data) {
				return "<null>";
			} else if (0 == data.length) {
				return "[] (empty)";
			}
			try {
				List<Record> records = Record.fromByteArray(data, ADDRESS);
				int max = records.size();
				StringBuilder builder = new StringBuilder();
				for (int index = 0; index < max;) {
					Record record = records.get(index);
					if (max == 1) {
						builder.append("rec(");
					} else {
						builder.append("rec(#").append(index).append(", ");
					}
					builder.append(record.getLength()).append(" bytes, ");
					if (record.isNewClientHello()) {
						builder.append("NEW CLIENT_HELLO");
					} else {
						builder.append(record.getType());
						builder.append(", Epoch=").append(record.getEpoch());
						builder.append(", RSeqNo=").append(record.getSequenceNumber());
						if (record.getType() == ContentType.HANDSHAKE && record.getEpoch() == 0) {
							byte[] fragment = record.getFragmentBytes();
							if (fragment != null && fragment.length > 6) {
								HandshakeType type = HandshakeType.getTypeByCode(fragment[0] & 0xff);
								int seqn = (fragment[4] & 0xff) << 8 | (fragment[5]  & 0xff);
								builder.append(", ").append(type).append(", HSeqNo=").append(seqn);
							}
						}
					}
					builder.append(")");
					if (++index < max) {
						builder.append(",");
					}
				}
				return builder.toString();
			} catch (RuntimeException ex) {
				return "decode " + data.length + " received bytes with " + ex.getMessage();
			}
		}
	
	};

	/**
	 * Create rule supporting provided modes.
	 * 
	 * @param modes supported datagram socket implementation modes.
	 */
	public DtlsNetworkRule(Mode... modes) {
		super(FORMATTER, modes);
	}

	@Override
	public DtlsNetworkRule setDelay(int delayInMillis) {
		return (DtlsNetworkRule) super.setDelay(delayInMillis);
	}

}
