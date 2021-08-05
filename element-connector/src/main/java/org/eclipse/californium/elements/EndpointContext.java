/*******************************************************************************
 * Copyright (c) 2016, 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - add support for correlation context to provide
 *                                      additional information to application layer for
 *                                      matching messages (fix GitHub issue #1)
 *    Achim Kraus (Bosch Software Innovations GmbH) - extend and rename 
 *                                      CorrelationContext into EndpointContext.
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.Map;

import org.eclipse.californium.elements.util.Bytes;

/**
 * A container for storing transport specific information about the context in
 * which a message has been sent or received.
 * 
 * Contains several endpoint identity candidates:
 * 
 * <table summary="Endpoint Identity Candidates">
 * <tr>
 * <th>Candidate</th>
 * <th>Description</th>
 * <th>Long-Term-Stable</th>
 * </tr>
 * <tr>
 * <td>InetSocketAddress</td>
 * <td>identity for plain coap according RFC7252</td>
 * <td>With IPv4 and NATs too frequently not long-term-stable</td>
 * </tr>
 * <tr>
 * <td>Principal</td>
 * <td>identity for secure endpoint, requires unique credentials per client</td>
 * <td>As stable as the credentials</td>
 * </tr>
 * <tr>
 * <td>DTLS Session, cipher suite, epoch</td>
 * <td>identity for secure coaps according RFC7252</td>
 * <td>With new or resumed DTLS session not long-term-stable</td>
 * </tr>
 * </table>
 * 
 * Note: with 3.0 the implementation is enhanced to support not only
 * {@link String} as attributes value, {@link Integer}, {@link Long},
 * {@link Boolean}, {@link InetSocketAddress} and {@link Bytes} are also
 * supported.
 */
public interface EndpointContext {

	/**
	 * Gets a value from this context.
	 * 
	 * @param <T> value type
	 * @param definition the definition to retrieve the value for.
	 * @return the value, or {@code null} if, this context does not contain a
	 *         value for the given definition.
	 * @since 3.0
	 */
	<T> T get(Definition<T> definition);

	/**
	 * Gets a {@link String} value from this context.
	 * 
	 * @param <T> value type
	 * @param definition the key to retrieve the value for.
	 * @return the value as {@link String}, or {@code null}, if this context
	 *         does not contain a value for the given definition. If the value
	 *         is a {@link Bytes}, {@link Bytes#getAsString()} is returned,
	 *         otherwise {@link Object#toString()} will be returned.
	 * @since 3.0
	 */
	<T> String getString(Definition<T> definition);

	/**
	 * Gets a Set of a Map.Entry which contains the key-value pair of the
	 * CorrelationContext.
	 * 
	 * The Set is intended to be "unmodifiable".
	 *
	 * @return A set of a map entry containing the key value pair.
	 * @since 3.0 (changed types of Map)
	 */
	Map<Definition<?>, Object> entries();

	/**
	 * Check, if the correlation information contained, contains critical
	 * entries relevant for matching. A context with critical entries will
	 * inhibit a new connection.
	 * 
	 * @return {@code true}, if critical entries contained, and no new
	 *         connection could match the correlation context provided in this
	 *         instance. {@code false}, if a new connection may match this
	 *         correlation context.
	 */
	boolean hasCriticalEntries();

	/**
	 * Gets the identity of the peer that the message is for or from.
	 * 
	 * @return identity of peer. {@code null}, if not available.
	 */
	Principal getPeerIdentity();

	/**
	 * Gets the inet address of the peer that the message is for or from.
	 * 
	 * @return address of peer
	 */
	InetSocketAddress getPeerAddress();

	/**
	 * Gets the name of the virtual host that this endpoint is scoped to.
	 * 
	 * @return the name or {@code null} if no virtual host is set.
	 */
	String getVirtualHost();

}
