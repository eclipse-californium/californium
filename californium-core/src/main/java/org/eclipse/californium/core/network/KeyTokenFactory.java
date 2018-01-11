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
import org.eclipse.californium.elements.EndpointContext;

/**
 * A factory interface to create {@link KeyToken} from {@link Token} and
 * {@link EndpointContext}.
 * </p>
 * Enables upper layers to supplement additional information extracted from the
 * context to identify exchanges and observes.
 */
public interface KeyTokenFactory {

	/**
	 * Create key token based on the provided token and context.
	 * 
	 * Depending on the implementation, the context must contain the specific
	 * information.
	 * 
	 * @param token token for the key
	 * @param context context for the key
	 * @return create key token
	 * @throws NullPointerException if {@code token} or {@code context} is
	 *             {@code null}.
	 * @throws IllegalArgumentException if {@code context} doesn't contain the
	 *             required data.
	 */
	KeyToken create(Token token, EndpointContext context);
}
