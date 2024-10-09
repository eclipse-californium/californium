/********************************************************************************
 * Copyright (c) 2023 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.core.coap.option;

import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionNumberRegistry.Names;

/**
 * Option registry with supported standard options.
 * 
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10" target=
 *      "_blank">RFC7252 5.10. Option Definitions</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7641#section-2" target=
 *      "_blank">RFC7641 2. The Observe Option</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7959#section-2.1" target=
 *      "_blank">RFC7959 2.1. The Block2 and Block1 Options</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7959#section-4" target=
 *      "_blank">RFC7959 4. The Size2 and Size1 Options</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7967.html#section-2" target=
 *      "_blank">RFC7967 2. Option Definition</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8613.html#section-2" target=
 *      "_blank">RFC8613 2. The OSCORE Option</a>
 * 
 * @since 3.8
 */
public class StandardOptionRegistry extends MapBasedOptionRegistry {

	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final OpaqueOptionDefinition IF_MATCH = new OpaqueOptionDefinition(OptionNumberRegistry.IF_MATCH,
			Names.If_Match, false, 0, 8);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final StringOptionDefinition URI_HOST = new StringOptionDefinition(OptionNumberRegistry.URI_HOST,
			Names.Uri_Host, true, 1, 255);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final OpaqueOptionDefinition ETAG = new OpaqueOptionDefinition(OptionNumberRegistry.ETAG, Names.ETag,
			false, 1, 8);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final EmptyOptionDefinition IF_NONE_MATCH = new EmptyOptionDefinition(
			OptionNumberRegistry.IF_NONE_MATCH, Names.If_None_Match);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final IntegerOptionDefinition URI_PORT = new IntegerOptionDefinition(OptionNumberRegistry.URI_PORT,
			Names.Uri_Port, true, 0, 2);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final StringOptionDefinition LOCATION_PATH = new StringOptionDefinition(
			OptionNumberRegistry.LOCATION_PATH, Names.Location_Path, false, 0, 255);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final StringOptionDefinition URI_PATH = new StringOptionDefinition(OptionNumberRegistry.URI_PATH,
			Names.Uri_Path, false, 0, 255);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final IntegerOptionDefinition CONTENT_FORMAT = new IntegerOptionDefinition(
			OptionNumberRegistry.CONTENT_FORMAT, Names.Content_Format, true, 0, 2);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final IntegerOptionDefinition MAX_AGE = new IntegerOptionDefinition(OptionNumberRegistry.MAX_AGE,
			Names.Max_Age, true, 0, 4);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final StringOptionDefinition URI_QUERY = new StringOptionDefinition(OptionNumberRegistry.URI_QUERY,
			Names.Uri_Query, false, 0, 255);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final IntegerOptionDefinition ACCEPT = new IntegerOptionDefinition(OptionNumberRegistry.ACCEPT,
			Names.Accept, true, 0, 2);
	/**
	 * Not supported for now, only for logging!
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc9177.html#section-4"
	 *      target= "_blank">RFC9177 4. The Q-Block1 and Q-Block2 Options </a>
	 * @since 3.9
	 */
	public static final IntegerOptionDefinition Q_BLOCK_1 = new IntegerOptionDefinition(19, "Q-Block-1", true, 0, 3);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final StringOptionDefinition LOCATION_QUERY = new StringOptionDefinition(
			OptionNumberRegistry.LOCATION_QUERY, Names.Location_Query, false, 0, 255);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final StringOptionDefinition PROXY_URI = new StringOptionDefinition(OptionNumberRegistry.PROXY_URI,
			Names.Proxy_Uri, true, 1, 1034);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final StringOptionDefinition PROXY_SCHEME = new StringOptionDefinition(
			OptionNumberRegistry.PROXY_SCHEME, Names.Proxy_Scheme, true, 1, 255);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final IntegerOptionDefinition SIZE1 = new IntegerOptionDefinition(OptionNumberRegistry.SIZE1,
			Names.Size1, true, 0, 4);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7641#section-2" target=
	 *      "_blank">RFC7641 2. The Observe Option</a>
	 */
	public static final IntegerOptionDefinition OBSERVE = new IntegerOptionDefinition(OptionNumberRegistry.OBSERVE,
			Names.Observe, true, 0, 3);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7959#section-2.1" target=
	 *      "_blank">RFC7959 2.1. The Block2 and Block1 Options</a>
	 */
	public static final IntegerOptionDefinition BLOCK1 = new IntegerOptionDefinition(OptionNumberRegistry.BLOCK1,
			Names.Block1, true, 0, 3);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7959#section-2.1" target=
	 *      "_blank">RFC7959 2.1. The Block2 and Block1 Options</a>
	 */
	public static final IntegerOptionDefinition BLOCK2 = new IntegerOptionDefinition(OptionNumberRegistry.BLOCK2,
			Names.Block2, true, 0, 3);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7959#section-4" target=
	 *      "_blank">RFC7959 4. The Size2 and Size1 Options</a>
	 */
	public static final IntegerOptionDefinition SIZE2 = new IntegerOptionDefinition(OptionNumberRegistry.SIZE2,
			Names.Size2, true, 0, 4);
	/**
	 * Not supported for now, only for logging!
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc9177.html#section-4"
	 *      target= "_blank">RFC9177 4. The Q-Block1 and Q-Block2 Options </a>
	 * @since 3.9
	 */
	public static final IntegerOptionDefinition Q_BLOCK_2 = new IntegerOptionDefinition(31, "Q-Block-2", false, 0, 3);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc8613.html#section-2"
	 *      target= "_blank">RFC8613 2. The OSCORE Option</a>
	 */
	public static final OpaqueOptionDefinition OSCORE = new OpaqueOptionDefinition(OptionNumberRegistry.OSCORE,
			Names.Object_Security, true, 0, 255);
	/**
	 * Not supported for now, only for logging!
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc9175.html#section-2.2.1"
	 *      target= "_blank">RFC9175 2.2.1. Echo Option Format</a>
	 * @since 3.9
	 */
	public static final OpaqueOptionDefinition ECHO = new OpaqueOptionDefinition(252, "Echo", true, 1, 40);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7967.html#section-2"
	 *      target= "_blank">RFC7967 2. Option Definition</a>
	 */
	public static final IntegerOptionDefinition NO_RESPONSE = new IntegerOptionDefinition(
			OptionNumberRegistry.NO_RESPONSE, Names.No_Response, true, 0, 1);
	/**
	 * Not supported for now, only for logging!
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc9175.html#section-3.2.1"
	 *      target= "_blank">RFC9175 3.2.1. Request-Tag Option Format </a>
	 * @since 3.9
	 */
	public static final OpaqueOptionDefinition REQUEST_TAG = new OpaqueOptionDefinition(292, "Request-Tag", false, 0,
			8);

	/**
	 * Registry with all standard options.
	 */
	public static final OptionRegistry STANDARD_OPTIONS = new StandardOptionRegistry();

	private StandardOptionRegistry() {
		super(IF_MATCH, URI_HOST, ETAG, IF_NONE_MATCH, URI_PORT, LOCATION_PATH, URI_PATH, CONTENT_FORMAT, MAX_AGE,
				URI_QUERY, ACCEPT, Q_BLOCK_1, LOCATION_QUERY, PROXY_URI, PROXY_SCHEME, SIZE1, OBSERVE, BLOCK1, BLOCK2,
				SIZE2, Q_BLOCK_2, OSCORE, ECHO, NO_RESPONSE, REQUEST_TAG);
	}

	/**
	 * Default option registry.
	 */
	private static volatile OptionRegistry defaultRegistry;

	static {
		setDefaultOptionRegistry(null);
	}

	/**
	 * Get default option registry.
	 * 
	 * @return the default option registry.
	 */
	public static OptionRegistry getDefaultOptionRegistry() {
		return defaultRegistry;
	}

	/**
	 * Set default option registry
	 * 
	 * @param registry default option registry. If {@code null}, use the
	 *            implementation default.
	 * @return previous default option registry.
	 */
	public static OptionRegistry setDefaultOptionRegistry(OptionRegistry registry) {
		OptionRegistry previous = defaultRegistry;
		if (registry == null) {
			defaultRegistry = STANDARD_OPTIONS;
		} else {
			defaultRegistry = registry;
		}
		return previous;
	}

}
