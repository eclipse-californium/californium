/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - introduce CorrelationContextMatcher
 *                                      (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - create CorrelationContextMatcher
 *                                      related to connector
 *    Achim Kraus (Bosch Software Innovations GmbH) - add TCP support
 *    Achim Kraus (Bosch Software Innovations GmbH) - rename CorrelationContextMatcherFactory
 *                                                    to EndpointContextMatcherFactroy.
 *                                                    Add PRINCIPAL mode.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add TlsEndpointContextMatcher
 *    Achim Kraus (Bosch Software Innovations GmbH) - extend strict/relaxed modes for
 *                                                    plain coap. 
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.MatcherMode;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.PrincipalAndAnonymousEndpointContextMatcher;
import org.eclipse.californium.elements.PrincipalEndpointContextMatcher;
import org.eclipse.californium.elements.RelaxedDtlsEndpointContextMatcher;
import org.eclipse.californium.elements.StrictDtlsEndpointContextMatcher;
import org.eclipse.californium.elements.TcpEndpointContextMatcher;
import org.eclipse.californium.elements.TlsEndpointContextMatcher;
import org.eclipse.californium.elements.UdpEndpointContextMatcher;
import org.eclipse.californium.elements.config.Configuration;

/**
 * Factory for endpoint context matcher.
 */
public class EndpointContextMatcherFactory {

	/**
	 * Creates endpoint context matcher related to connector according the
	 * configuration.
	 * <p>
	 * If connector supports "DTLS", COAP.RESPONSE_MATCHING is used to
	 * determine, if {@link StrictDtlsEndpointContextMatcher},
	 * {@link RelaxedDtlsEndpointContextMatcher}, or
	 * {@link PrincipalEndpointContextMatcher} is used.
	 * <p>
	 * If connector supports "UDP", COAP.RESPONSE_MATCHING is used to determine,
	 * if {@link UdpEndpointContextMatcher} is used with disabled
	 * ({@link MatcherMode#RELAXED}) or enabled address check (otherwise).
	 * <p>
	 * For other protocol flavors the corresponding matcher is used.
	 * 
	 * @param connector connector to create related endpoint context matcher.
	 * @param config configuration.
	 * @return endpoint context matcher
	 * @throws NullPointerException if one of the provided arguments is
	 *             {@code null}
	 * @throws IllegalArgumentException if the protocol of the connector is not
	 *             supported.
	 * @since 4.0 (added exceptions)
	 */
	public static EndpointContextMatcher create(Connector connector, Configuration config) {
		if (connector == null) {
			throw new NullPointerException("Connector must not be null!");
		}
		return create(connector.getProtocol(), false, config);
	}

	/**
	 * Creates endpoint context matcher related to the protocol according the
	 * configuration.
	 * <p>
	 * For "DTLS" COAP.RESPONSE_MATCHING is used to determine, if
	 * {@link StrictDtlsEndpointContextMatcher},
	 * {@link RelaxedDtlsEndpointContextMatcher}, or
	 * {@link PrincipalEndpointContextMatcher} is used. If PRINCIPAL_IDENTITY is
	 * used for COAP.RESPONSE_MATCHING and anonymous clients are enabled, then
	 * {@link PrincipalAndAnonymousEndpointContextMatcher} is used. Anonymous
	 * clients are only implemented for DTLS, see
	 * DTLS.CLIENT_AUTHENTICATION_MODE and DTLS.DTLS_APPLICATION_AUTHORIZATION.
	 * <p>
	 * For "UDP", COAP.RESPONSE_MATCHING is used to determine, if
	 * {@link UdpEndpointContextMatcher} is used with disabled
	 * ({@link MatcherMode#RELAXED}) or enabled address check (otherwise).
	 * <p>
	 * For other protocol flavors the corresponding matcher is used.
	 * 
	 * @param protocol protocol.
	 * @param anonymous {@code true} if anonymous clients must be supported.
	 * @param config configuration.
	 * @return endpoint context matcher
	 * @throws NullPointerException if one of the provided arguments is
	 *             {@code null}
	 * @throws IllegalArgumentException if the protocol is not supported.
	 * @since 4.0
	 */
	public static EndpointContextMatcher create(String protocol, boolean anonymous, Configuration config) {
		if (protocol == null) {
			throw new NullPointerException("Protocol must not be null!");
		}
		if (config == null) {
			throw new NullPointerException("Configuration must not be null!");
		}
		if (CoAP.PROTOCOL_TCP.equalsIgnoreCase(protocol)) {
			return new TcpEndpointContextMatcher();
		} else if (CoAP.PROTOCOL_TLS.equalsIgnoreCase(protocol)) {
			return new TlsEndpointContextMatcher();
		}

		MatcherMode mode = config.get(CoapConfig.RESPONSE_MATCHING);
		if (CoAP.PROTOCOL_UDP.equalsIgnoreCase(protocol)) {
			switch (mode) {
			case RELAXED:
				return new UdpEndpointContextMatcher(false);
			case PRINCIPAL:
			case PRINCIPAL_IDENTITY:
			case STRICT:
			default:
				return new UdpEndpointContextMatcher(true);
			}
		} else if (CoAP.PROTOCOL_DTLS.equalsIgnoreCase(protocol)) {
			switch (mode) {
			case RELAXED:
				return new RelaxedDtlsEndpointContextMatcher();
			case PRINCIPAL:
				return new PrincipalEndpointContextMatcher();
			case PRINCIPAL_IDENTITY:
				if (anonymous) {
					return new PrincipalAndAnonymousEndpointContextMatcher();
				} else {
					return new PrincipalEndpointContextMatcher(true);
				}
			case STRICT:
			default:
				return new StrictDtlsEndpointContextMatcher();
			}
		}
		throw new IllegalArgumentException("Protocol " + protocol + " is not supported!");
	}
}
