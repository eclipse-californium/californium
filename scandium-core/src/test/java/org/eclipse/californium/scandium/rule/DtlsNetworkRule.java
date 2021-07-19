/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.rule;

import java.util.List;

import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.NetworkRule;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DatagramFormatter;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsRole;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.HandshakeType;
import org.eclipse.californium.scandium.dtls.Record;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

	public static final Logger LOGGER = LoggerFactory.getLogger(DtlsNetworkRule.class);

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
				List<Record> records = DtlsTestTools.fromByteArray(data, null, ClockUtil.nanoRealtime());
				int max = records.size();
				StringBuilder builder = new StringBuilder();
				for (int index = 0; index < max;) {
					Record record = records.get(index);
					if (max == 1) {
						builder.append("rec(");
					} else {
						builder.append("rec(#").append(index).append(", ");
					}
					builder.append(record.getFragmentLength()).append(" bytes, ");
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
								int seqn = (fragment[4] & 0xff) << 8 | (fragment[5] & 0xff);
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

	/**
	 * Create new configuration for testing.
	 * 
	 * @return configurations. Detached from the standard configuration.
	 */
	@Override
	public Configuration createTestConfig() {
		DtlsConfig.register();
		Configuration config = super.createTestConfig();
		return config;
	}

	/**
	 * Create new client configuration for testing.
	 * 
	 * @return configurations. Detached from the standard configuration.
	 */
	public Configuration createClientTestConfig() {
		Configuration config = createTestConfig();
		config.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
		return config;
	}

	/**
	 * Create new server configuration for testing.
	 * 
	 * @return configurations. Detached from the standard configuration.
	 */
	public Configuration createServerTestConfig() {
		Configuration config = createTestConfig();
		config.set(DtlsConfig.DTLS_ROLE, DtlsRole.SERVER_ONLY);
		return config;
	}
}
