/*******************************************************************************
+ * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
+ * 
+ * All rights reserved. This program and the accompanying materials
+ * are made available under the terms of the Eclipse Public License v2.0
+ * and Eclipse Distribution License v1.0 which accompany this distribution.
+ * 
+ * The Eclipse Public License is available at
+ *    http://www.eclipse.org/legal/epl-v20.html
+ * and the Eclipse Distribution License is available at
+ *    http://www.eclipse.org/org/documents/edl-v10.html.
+ * 
+ * Contributors:
+ *    Bosch Software Innovations GmbH - initial implementation. 
+ *    Rikard Höglund (RISE)           - OSCORE TCP stack creation
+ ******************************************************************************/
package org.eclipse.californium.oscore;

import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.ExtendedCoapStackFactory;
import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.config.Configuration;

/**
 * Coap stack factory creating a {@link OSCoreUdpStack} or
 * {@link OSCoreTcpStack} including a {@link ObjectSecurityLayer}.
 */
public class OSCoreCoapStackFactory implements ExtendedCoapStackFactory {

	private static AtomicBoolean init = new AtomicBoolean();
	private static volatile OSCoreCtxDB defaultCtxDb;

	@Override
	public CoapStack createCoapStack(String protocol, String tag, Configuration config,
			EndpointContextMatcher matchingStrategy, Outbox outbox, Object customStackArgument) {

		OSCoreCtxDB ctxDb = defaultCtxDb;
		if (customStackArgument != null) {
			if (!(customStackArgument instanceof OSCoreCtxDB)) {
				throw new IllegalArgumentException(
						"custom argument must be a OSCoreCtxDB, not " + customStackArgument.getClass() + "!");
			}
			ctxDb = (OSCoreCtxDB) customStackArgument;
		}

		if (CoAP.isTcpProtocol(protocol)) {
			return new OSCoreTcpStack(tag, config, matchingStrategy, outbox, ctxDb);
		} else {
			return new OSCoreUdpStack(tag, config, matchingStrategy, outbox, ctxDb);
		}
	}

	@Override
	public CoapStack createCoapStack(String protocol, String tag, Configuration config, Outbox outbox,
			Object customStackArgument) {
		return createCoapStack(protocol, tag, config, null, outbox, customStackArgument);
	}

	/**
	 * Use {@link OSCoreUdpStack} or {@link OSCoreTcpStack} as default for
	 * {@link CoapEndpoint}.
	 * 
	 * Note: the factory is only applied once with the first call, the
	 * {@link #defaultCtxDb} is update on every call.
	 * 
	 * @param defaultCtxDb default context DB. Passed in as default argument for
	 *            {@link OSCoreUdpStack} and {@link OSCoreTcpStack}
	 * 
	 * @see CoapEndpoint#setDefaultCoapStackFactory(CoapStackFactory)
	 */
	public static void useAsDefault(OSCoreCtxDB defaultCtxDb) {
		if (init.compareAndSet(false, true)) {
			CoapEndpoint.setDefaultCoapStackFactory(new OSCoreCoapStackFactory());
		}
		OSCoreCoapStackFactory.defaultCtxDb = defaultCtxDb;
	}
}
