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
 *    Bosch Software Innovations GmbH - introduce CorrelationContextMatcher
 *                                      (fix GitHub issue #104)
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.CorrelationContextMatcher;
import org.eclipse.californium.elements.RelaxedCorrelationContextMatcher;
import org.eclipse.californium.elements.StrictCorrelationContextMatcher;

/**
 * Factory for correlation context matcher.
 */
public class CorrelationContextMatcherFactory {

	/**
	 * Create correlation context matcher according the configuration. If
	 * USE_STRICT_RESPONSE_MATCHING is set, use
	 * {@link StrictCorrelationContextMatcher}, otherwise
	 * {@link RelaxedCorrelationContextMatcher}.
	 * 
	 * @param config configuration.
	 * @return correlation context matcher
	 */
	public static CorrelationContextMatcher create(NetworkConfig config) {
		return config.getBoolean(NetworkConfig.Keys.USE_STRICT_RESPONSE_MATCHING) ? new StrictCorrelationContextMatcher()
				: new RelaxedCorrelationContextMatcher();
	}
}
