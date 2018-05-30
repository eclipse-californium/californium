/*******************************************************************************
+ * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
+ * 
+ * All rights reserved. This program and the accompanying materials
+ * are made available under the terms of the Eclipse Public License v1.0
+ * and Eclipse Distribution License v1.0 which accompany this distribution.
+ * 
+ * The Eclipse Public License is available at
+ *    http://www.eclipse.org/legal/epl-v10.html
+ * and the Eclipse Distribution License is available at
+ *    http://www.eclipse.org/org/documents/edl-v10.html.
+ * 
+ * Contributors:
+ *    Bosch Software Innovations GmbH - initial implementation. 
+ ******************************************************************************/
package org.eclipse.californium.oscore;

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

	@Override
	public CoapStack createCoapStack(String protocol, NetworkConfig config, Outbox outbox) {
		if (CoAP.isTcpProtocol(protocol)) {
			throw new IllegalArgumentException("protocol \"" + protocol + "\" is not supported!");
		}
		return new OSCoreStack(config, outbox);
	}

	/**
	 * Use {@link OSCoreStack} as default for {@link CoapEndpoint}.
	 * 
	 * @see CoapEndpoint.#setDefaultCoapStackFactory(CoapStackFactory)
	 */
	public static void useAsDefault() {
		CoapEndpoint.setDefaultCoapStackFactory(new OSCoreCoapStackFactory());
	}
}
