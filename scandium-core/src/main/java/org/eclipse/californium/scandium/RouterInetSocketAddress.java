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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.net.InetSocketAddress;

/**
 * InetSocketAddress containing a router address as well.
 * 
 * @since 2.5
 */
public class RouterInetSocketAddress extends InetSocketAddress {

	private static final long serialVersionUID = 135792468L;

	private final InetSocketAddress router;

	public RouterInetSocketAddress(InetSocketAddress addr, InetSocketAddress router) {
		super(addr.getAddress(), addr.getPort());
		this.router = router;
	}

	public InetSocketAddress getRouter() {
		return router;
	}
}
