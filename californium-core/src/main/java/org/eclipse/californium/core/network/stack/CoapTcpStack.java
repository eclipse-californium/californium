/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Matthias Kovatsch - creator and main architect
 * Martin Lanter - architect and re-implementation
 * Dominique Im Obersteg - parsers and initial implementation
 * Daniel Pauli - parsers and initial implementation
 * Kai Hudalla - logging
 * Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 * explicit String concatenation
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * Achim Kraus (Bosch Software Innovations GmbH) - move common function to BaseCoapStack
 * Achim Kraus (Bosch Software Innovations GmbH) - add TcpExchangeCleanupLayer
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.config.Configuration;

/**
 * The CoapTcpStack builds up the stack of CoAP layers that process the CoAP
 * protocol when running over TCP connection.
 * <p>
 * The complete process for incoming and outgoing messages is visualized below.
 * The class {@link CoapStack} builds up the part between the Stack Top and
 * Bottom.
 * <hr><blockquote><pre>
 * +--------------------------+
 * | {@link MessageDeliverer}         |
 * +--------------A-----------+
 *                A
 *              * A
 * +------------+-A-----------+
 * |        CoAPEndpoint      |
 * |            v A           |
 * |            v A           |
 * | +----------v-+---------+ |
 * | | Stack Top            | |
 * | +----------------------+ |
 * | | {@link TcpExchangeCleanupLayer} | |
 * | +----------------------+ |
 * | | {@link TcpObserveLayer}      | |
 * | +----------------------+ |
 * | | {@link BlockwiseLayer}       | |
 * | +----------------------+ |
 * | | {@link TcpAdaptionLayer}     | |
 * | +----------------------+ |
 * | | Stack Bottom         | |
 * | +----------+-A---------+ |
 * |            v A           |
 * |          Matcher         |
 * |            v A           |
 * |        Interceptor       |
 * |            v A           |
 * +------------v-A-----------+
 *              v A 
 *              v A 
 * +------------v-+-----------+
 * | {@link Connector}                |
 * +--------------------------+
 * </pre></blockquote><hr>
 */
public class CoapTcpStack extends BaseCoapStack {

	/**
	 * Creates a new stack using TCP as the transport.
	 * 
	 * @param tag logging tag
	 * @param config The configuration values to use.
	 * @param matchingStrategy endpoint context matcher to relate responses with
	 *            requests
	 * @param outbox The adapter for submitting outbound messages to the
	 *            transport.
	 * @since 3.1
	 */
	public CoapTcpStack(String tag, Configuration config, EndpointContextMatcher matchingStrategy, Outbox outbox) {
		super(outbox);

		Layer layers[] = new Layer[] { new TcpExchangeCleanupLayer(), new TcpObserveLayer(config),
				new BlockwiseLayer(tag, true, config, matchingStrategy), new TcpAdaptionLayer() };

		setLayers(layers);

		// make sure the endpoint sets a MessageDeliverer
	}

	/**
	 * Creates a new stack using TCP as the transport.
	 * 
	 * @param tag logging tag
	 * @param config The configuration values to use.
	 * @param outbox The adapter for submitting outbound messages to the
	 *            transport.
	 * @deprecated use
	 *             {@link #CoapTcpStack(String, Configuration, EndpointContextMatcher, Outbox)}
	 *             instead.
	 * @since 3.0 (logging tag added and changed parameter to Configuration)
	 */
	public CoapTcpStack(String tag, Configuration config, Outbox outbox) {
		this(tag, config, null, outbox);
	}
}
