/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust comment for
 *                                                    contextEstablished.
 *                                                    issue #311
 *    Achim Kraus (Bosch Software Innovations GmbH) - add remove to ensure 
 *                                                    message exchange house-keeping
 *    Achim Kraus (Bosch Software Innovations GmbH) - move onContextEstablished
 *                                                    to MessageObserver.
 *                                                    Issue #487
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign into RemoveHandler
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Exchange.KeyMID;

/**
 * The remove handler can be set to an {@link Exchange} and will be invoked
 * for release the exchange from the exchange store.
 */
public interface RemoveHandler {

	/**
	 * Remove exchange from store.
	 * 
	 * @param exchange exchange to remove from store
	 * @param token token to remove exchange. Maybe {@code null}.
	 * @param key mid key to remove exchange. Maybe {@code null}.
	 */
	void remove(Exchange exchange, Token token, KeyMID key);
}
