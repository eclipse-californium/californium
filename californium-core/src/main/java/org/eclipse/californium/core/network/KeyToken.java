/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial API
 *******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.observe.ObservationStore;

/**
 * A interface to enable a {@link Token} to be used as bas for a key for
 * {@link MessageExchangeStore} and {@link ObservationStore}.
 */
public interface KeyToken {

	/**
	 * Returns the related token.
	 * 
	 * @return related token
	 */
	Token getToken();
}
