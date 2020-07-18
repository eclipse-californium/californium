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
+ ******************************************************************************/
package org.eclipse.californium.oscore;

import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapStackFactory;
import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.CoapStack;

/**
 * Coap stack factory creating a {@link OSCoreStack} including a
 * {@link ObjectSecurityLayer}.
 */
public class OSCoreCoapStackFactory implements CoapStackFactory {

	private static AtomicBoolean init = new AtomicBoolean();
	private static volatile OSCoreCtxDB defaultCtxDb;

	@Override
	public CoapStack createCoapStack(String protocol, NetworkConfig config, Outbox outbox, Object customStackArgument) {
		if (CoAP.isTcpProtocol(protocol)) {
			throw new IllegalArgumentException("protocol \"" + protocol + "\" is not supported!");
		}
		OSCoreCtxDB ctxDb = defaultCtxDb;
		if (customStackArgument != null) {
			ctxDb = (OSCoreCtxDB) customStackArgument;
		}
		return new OSCoreStack(config, outbox, ctxDb);
	}

	/**
	 * Use {@link OSCoreStack} as default for {@link CoapEndpoint}.
	 * 
	 * Note: the factory is only applied once with the first call, the
	 * {@link #defaultCtxDb} is update on every call.
	 * 
	 * @param defaultCtxDb default context DB. Passed in as default argument for {@link OSCoreStack}
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
