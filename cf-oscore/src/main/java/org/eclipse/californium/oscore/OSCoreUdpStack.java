/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Joakim Brorsson
 *    Ludwig Seitz (RISE SICS)
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.stack.BaseCoapStack;
import org.eclipse.californium.core.network.stack.BlockwiseLayer;
import org.eclipse.californium.core.network.stack.CongestionControlLayer;
import org.eclipse.californium.core.network.stack.ExchangeCleanupLayer;
import org.eclipse.californium.core.network.stack.Layer;
import org.eclipse.californium.core.network.stack.ObserveLayer;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.config.Configuration;

/**
 * UDP CoAP stack supporting OSCORE.
 * 
 * Extends the BaseCoapStack and adds the ObjectSecurityLayer.
 *
 */
public class OSCoreUdpStack extends BaseCoapStack {
	
	/**
	 * Creates a new OSCORE-enabled stack using UDP as the transport.
	 * 
	 * @param tag logging tag
	 * @param config The configuration values to use.
	 * @param matchingStrategy endpoint context matcher to relate responses with
	 *            requests
	 * @param outbox The adapter for submitting outbound messages to the
	 *            transport.
	 * @param ctxDb context DB.
	 * @since 3.1
	 */
	public OSCoreUdpStack(String tag, Configuration config, EndpointContextMatcher matchingStrategy, Outbox outbox, OSCoreCtxDB ctxDb) {
		super(outbox);

		Layer layers[] = new Layer[] {
				new ObjectSecurityContextLayer(ctxDb),
				new ExchangeCleanupLayer(config),
				new ObserveLayer(config),
				new BlockwiseLayer(tag, false, config, matchingStrategy),
				CongestionControlLayer.newImplementation(tag, config),
				new ObjectSecurityLayer(ctxDb)};
		setLayers(layers);
	}
}
