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
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.elements.EndpointContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Endpoint Context tracer.
 * 
 * Calls {@link #onContextChanged(EndpointContext)}, if the endpoint context
 * changes. The default implementation logs a pretty printed endpoint context.
 * 
 * @since 2.3
 */
public class EndpointContextTracer extends MessageObserverAdapter {

	private final static Logger LOGGER = LoggerFactory.getLogger(EndpointContextTracer.class);

	private final AtomicReference<EndpointContext> endpointContext = new AtomicReference<EndpointContext>();

	@Override
	public void onContextEstablished(EndpointContext endpointContext) {
		if (this.endpointContext.compareAndSet(null, endpointContext)) {
			onContextChanged(endpointContext);
		}
	}

	/**
	 * Get current endpoint context.
	 * 
	 * @return current endpoint context
	 * @since 3.0
	 */
	public EndpointContext getCurrentContext() {
		return endpointContext.get();
	}

	/**
	 * Invoked when the resulting endpoint context is changing.
	 * 
	 * Note: usually this callback must be processed in a synchronous manner,
	 * because on returning, the message is sent. Therefore take special care in
	 * methods called on this callback.
	 * 
	 * @param endpointContext changed endpoint context 
	 */
	protected void onContextChanged(EndpointContext endpointContext) {
		if (LOGGER.isInfoEnabled()) {
			LOGGER.info("{}", Utils.prettyPrint(endpointContext));
		}
	}
}
