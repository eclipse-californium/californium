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
 * 
 * Creates key mid using the peer's identity.
 */
public class PrincipalKeyMidGenerator implements KeyMidGenerator {

	@Override
	public KeyMID getKeyMid(int mid, EndpointContext peer) {
		return new KeyMID(mid, peer.getPeerIdentity());
	}
}
