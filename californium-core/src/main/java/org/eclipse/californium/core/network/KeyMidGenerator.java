/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *     Achim Kraus (Bosch Software Innovations GmbH) - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.elements.EndpointContext;

/**
 * Key MID generator.
 */
public interface KeyMidGenerator {

	/**
	 * Create a key MID.
	 * 
	 * @param mid the message MID
	 * @param context the endpoint context of the message.
	 * @return key mid
	 * @throws NullPointerException if the peer is {@code null}.
	 */
	KeyMID getKeyMid(int mid, EndpointContext peer);
}
