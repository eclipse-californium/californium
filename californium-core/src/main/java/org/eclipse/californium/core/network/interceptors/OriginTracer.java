/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use EndpointContext
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - reduce trace to 
 *                                                    InetSocketAddress
 ******************************************************************************/
package org.eclipse.californium.core.network.interceptors;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An interceptor which logs the source IP addresses of incoming requests.
 * <p>
 * In order to make proper use of this interceptor, the CoAP server should
 * be started with the <em>logback-sandbox.xml</em> logback configuration file
 * in the project's base directory.
 * <p>
 * This can be done by means of setting the <em>logback.configurationFile</em>
 * system property on the command line when starting the JVM, e.g.:
 * <pre>
 * java -Dlogback.configurationFile=/path/to/logback.sandbox.xml ...
 * </pre>
 * <p>
 * The gathered data is used for the Eclipse IoT metrics.
 */
public final class OriginTracer extends MessageInterceptorAdapter {

	private static final Logger LOGGER = LoggerFactory.getLogger(OriginTracer.class);

	@Override
	public void receiveRequest(Request request) {
		LOGGER.trace("{}", StringUtil.toLog(request.getSourceContext().getPeerAddress()));
	}

	@Override
	public void receiveEmptyMessage(EmptyMessage message) {
		// only log pings
		if (message.getType() == Type.CON) {
			LOGGER.trace("{}", StringUtil.toLog(message.getSourceContext().getPeerAddress()));
		}
	}
}
