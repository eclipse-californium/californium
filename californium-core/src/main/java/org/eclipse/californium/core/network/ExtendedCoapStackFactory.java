/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.Map;

import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.PublicAPIExtension;

/**
 * Factory for CoapStack supporting blockwise follow-up request matching.
 * 
 * Either provided to the {@link CoapEndpoint.Builder} or set as
 * default {@link CoapEndpoint#setDefaultCoapStackFactory(CoapStackFactory)}.
 * 
 * @since 3.1
 */
@SuppressWarnings("deprecation")
@PublicAPIExtension(type = CoapStackFactory.class)
public interface ExtendedCoapStackFactory extends CoapStackFactory {

	/**
	 * Create CoapStack.
	 * 
	 * @param protocol used protocol, values see
	 *            {@link Connector#getProtocol()}.
	 * @param tag logging tag
	 * @param config configuration used for this coap stack
	 * @param matchingStrategy endpoint context matcher to relate responses with
	 *            requests
	 * @param outbox outbox to be used for this coap stack
	 * @param customStackArgument argument for custom stack, if required.
	 *            {@code null} for standard stacks, or if the custom stack
	 *            doesn't require specific arguments. Maybe a {@link Map}, if
	 *            multiple arguments are required.
	 * @return create coap stack-
	 * @throws NullPointerException if any parameter is {@code null}
	 * @throws IllegalArgumentException if protocol is not supported.
	 */
	CoapStack createCoapStack(String protocol, String tag, Configuration config, EndpointContextMatcher matchingStrategy, Outbox outbox, Object customStackArgument);
}
