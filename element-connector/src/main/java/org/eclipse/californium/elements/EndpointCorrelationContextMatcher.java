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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements;

/**
 * Endpoint correlation context matcher. Matches based on endpoint identifier.
 */
public class EndpointCorrelationContextMatcher extends KeySetCorrelationContextMatcher {

	private static final String KEYS[] = { CorrelationContext.KEY_ENDPOINT_ID };

	public EndpointCorrelationContextMatcher() {
		super("endpoint correlation", KEYS);
	}

	@Override
	public boolean isToBeSent(CorrelationContext messageContext, CorrelationContext connectorContext) {
		if (null != messageContext && null == connectorContext) {
			String id = messageContext.get(CorrelationContext.KEY_ENDPOINT_ID);
			return null != id && !id.isEmpty();
		}
		return super.isToBeSent(messageContext, connectorContext);
	}

}
