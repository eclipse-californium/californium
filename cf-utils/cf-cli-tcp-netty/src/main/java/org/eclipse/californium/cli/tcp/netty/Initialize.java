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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.cli.tcp.netty;

import org.eclipse.californium.cli.ClientInitializer;
import org.eclipse.californium.core.coap.CoAP;

/**
 * Initialize {@link ClientInitializer}.
 * 
 * Register netty tcp connector factories.
 * 
 * @since 2.4
 */
public class Initialize {

	static {
		ClientInitializer.registerConnectorFactory(CoAP.PROTOCOL_TCP, new TcpConnectorFactory());
		ClientInitializer.registerConnectorFactory(CoAP.PROTOCOL_TLS, new TlsConnectorFactory());
	}

}
