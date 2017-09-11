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
 *    Achim Kraus (Bosch Software Innovations GmbH) - create CorrelationContextMatcher
 *                                      related to connector
 *    Achim Kraus (Bosch Software Innovations GmbH) - add TCP support
 *    Achim Kraus (Bosch Software Innovations GmbH) - rename CorrelationContextMatcherFactory
 *                                                    to EndpointContextMatcherFactroy.
 *                                                    Add PRINCIPAL mode.
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.PrincipalEndpointContextMatcher;
import org.eclipse.californium.elements.RelaxedDtlsEndpointContextMatcher;
import org.eclipse.californium.elements.StrictDtlsEndpointContextMatcher;
import org.eclipse.californium.elements.TcpEndpointContextMatcher;
import org.eclipse.californium.elements.UdpCorrelationContextMatcher;

/**
 * Factory for correlation context matcher.
 */
public class EndpointContextMatcherFactory {
	
	public enum DtlsMode {
		STRICT, RELAXED, PRINCIPAL
	}

	/**
	 * Create correlation context matcher related to connector according the
	 * configuration. If connector supports "coaps:" and
	 * USE_STRICT_RESPONSE_MATCHING is set, use
	 * {@link StrictDtlsEndpointContextMatcher}, otherwise
	 * {@link RelaxedDtlsEndpointContextMatcher}. For other protocol flavors
	 * the corresponding matcher is used. Note: currently the TLS based
	 * correlation context matcher is still missing and therefore for backwards
	 * compatibility the DTLS ones are used.
	 * 
	 * @param connector connector to create related correlation context matcher.
	 * @param config configuration.
	 * @return correlation context matcher
	 */
	public static EndpointContextMatcher create(Connector connector, NetworkConfig config) {
		if (null != connector) {
			if (connector.isSchemeSupported(CoAP.COAP_URI_SCHEME)) {
				return new UdpCorrelationContextMatcher();
			} else if (connector.isSchemeSupported(CoAP.COAP_SECURE_TCP_URI_SCHEME)) {
				/*
				 * To be implemented in a future PR, in the meanwhile use
				 * default dtls matcher as default for backwards compatibility
				 */
			} else if (connector.isSchemeSupported(CoAP.COAP_TCP_URI_SCHEME)) {
				return new TcpEndpointContextMatcher();
			}
		}
		String textualMode = "???";
		DtlsMode mode = DtlsMode.STRICT;
		try {
			textualMode = config.getString(NetworkConfig.Keys.DTLS_RESPONSE_MATCHING);
			mode = DtlsMode.valueOf(textualMode);
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("DTLS response matching mode '" + textualMode + "' not supported!");
		} catch (NullPointerException e) {
			throw new IllegalArgumentException("DTLS response matching mode not provided/configured!");
		}
		switch(mode) {
		case STRICT: 
			break;
		case RELAXED:
			return new RelaxedDtlsEndpointContextMatcher();
		case PRINCIPAL:
			return new PrincipalEndpointContextMatcher();
		}
		return new StrictDtlsEndpointContextMatcher();
	}
}
