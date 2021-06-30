/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
package org.eclipse.californium.integration.test.util;

import org.eclipse.californium.elements.util.DatagramFormatter;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CoAPs network rules for junit test using datagram sockets.
 *
 * The rule is intended to be mainly used as <code>&#64;ClassRule<code>
 * 
 * <pre>
 * public class AbcNetworkTest {
 *    &#64;ClassRule
 *    public static CoapsNetworkRule network = new CoapsNetworkRule(Mode.DIRECT, Mode.NATIVE);
 *    ...
 * </pre>
 */
public class CoapsNetworkRule extends CoapNetworkRule {

	public static final Logger LOGGER = LoggerFactory.getLogger(CoapsNetworkRule.class);

	/**
	 * Null formatter, data is encrypted, so nothign useful for logging.
	 */
	private static final DatagramFormatter NO_FORMATTER = null;

	/**
	 * Create rule supporting provided modes.
	 * 
	 * @param modes supported datagram socket implementation modes.
	 */
	public CoapsNetworkRule(Mode... modes) {
		super(NO_FORMATTER, modes);
		DtlsConfig.register();
	}
}
