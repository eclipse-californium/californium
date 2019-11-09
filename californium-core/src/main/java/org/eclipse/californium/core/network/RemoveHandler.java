/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - replace ExchangeObserver.
 ******************************************************************************/
package org.eclipse.californium.core.network;

/**
 * The remove handler can be set to an {@link Exchange} and will be invoked
 * for release the exchange from the exchange store.
 */
public interface RemoveHandler {

	/**
	 * Remove exchange from store.
	 * 
	 * @param exchange exchange to remove from store
	 * @param keyToken token to remove exchange. Maybe {@code null}.
	 * @param keyMID mid key to remove exchange. Maybe {@code null}.
	 */
	void remove(Exchange exchange, KeyToken keyToken, KeyMID keyMID);
}
