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
	public static final OpaqueOption.Definition IF_MATCH = new OpaqueOption.Definition(OptionNumberRegistry.IF_MATCH,
			Names.If_Match, false, 0, 8);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final StringOption.Definition URI_HOST = new StringOption.Definition(OptionNumberRegistry.URI_HOST,
			Names.Uri_Host, true, 1, 255);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final OpaqueOption.Definition ETAG = new OpaqueOption.Definition(OptionNumberRegistry.ETAG, Names.ETag,
			false, 1, 8);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final EmptyOption.Definition IF_NONE_MATCH = new EmptyOption.Definition(
			OptionNumberRegistry.IF_NONE_MATCH, Names.If_None_Match);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final IntegerOption.Definition URI_PORT = new IntegerOption.Definition(OptionNumberRegistry.URI_PORT,
			Names.Uri_Port, true, 0, 2);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final StringOption.Definition LOCATION_PATH = new StringOption.Definition(
			OptionNumberRegistry.LOCATION_PATH, Names.Location_Path, false, 0, 255);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final StringOption.Definition URI_PATH = new StringOption.Definition(OptionNumberRegistry.URI_PATH,
			Names.Uri_Path, false, 0, 255);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final IntegerOption.Definition CONTENT_FORMAT = new IntegerOption.Definition(
			OptionNumberRegistry.CONTENT_FORMAT, Names.Content_Format, true, 0, 2);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final IntegerOption.Definition MAX_AGE = new IntegerOption.Definition(OptionNumberRegistry.MAX_AGE,
			Names.Max_Age, true, 0, 4);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final StringOption.Definition URI_QUERY = new StringOption.Definition(OptionNumberRegistry.URI_QUERY,
			Names.Uri_Query, false, 0, 255);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final IntegerOption.Definition ACCEPT = new IntegerOption.Definition(OptionNumberRegistry.ACCEPT,
			Names.Accept, true, 0, 2);
	/**
	 * Not supported for now, only for logging!
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc9177.html#section-4"
	 *      target= "_blank">RFC9177 4. The Q-Block1 and Q-Block2 Options </a>
	 * @since 3.9
	 */
	public static final IntegerOption.Definition Q_BLOCK_1 = new IntegerOption.Definition(19, "Q-Block-1", true, 0, 3);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final StringOption.Definition LOCATION_QUERY = new StringOption.Definition(
			OptionNumberRegistry.LOCATION_QUERY, Names.Location_Query, false, 0, 255);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final StringOption.Definition PROXY_URI = new StringOption.Definition(OptionNumberRegistry.PROXY_URI,
			Names.Proxy_Uri, true, 1, 1034);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final StringOption.Definition PROXY_SCHEME = new StringOption.Definition(
			OptionNumberRegistry.PROXY_SCHEME, Names.Proxy_Scheme, true, 1, 255);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.10"
	 *      target= "_blank">RFC7252 5.10. Option Definitions</a>
	 */
	public static final IntegerOption.Definition SIZE1 = new IntegerOption.Definition(OptionNumberRegistry.SIZE1,
			Names.Size1, true, 0, 4);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7641#section-2" target=
	 *      "_blank">RFC7641 2. The Observe Option</a>
	 */
	public static final IntegerOption.Definition OBSERVE = new IntegerOption.Definition(OptionNumberRegistry.OBSERVE,
			Names.Observe, true, 0, 3);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7959#section-2.1" target=
	 *      "_blank">RFC7959 2.1. The Block2 and Block1 Options</a>
	 */
	public static final BlockOption.Definition BLOCK1 = new BlockOption.Definition(OptionNumberRegistry.BLOCK1,
			Names.Block1);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7959#section-2.1" target=
	 *      "_blank">RFC7959 2.1. The Block2 and Block1 Options</a>
	 */
	public static final BlockOption.Definition BLOCK2 = new BlockOption.Definition(OptionNumberRegistry.BLOCK2,
			Names.Block2);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7959#section-4" target=
	 *      "_blank">RFC7959 4. The Size2 and Size1 Options</a>
	 */
	public static final IntegerOption.Definition SIZE2 = new IntegerOption.Definition(OptionNumberRegistry.SIZE2,
			Names.Size2, true, 0, 4);
	/**
	 * Not supported for now, only for logging!
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc9177.html#section-4"
	 *      target= "_blank">RFC9177 4. The Q-Block1 and Q-Block2 Options </a>
	 * @since 3.9
	 */
	public static final IntegerOption.Definition Q_BLOCK_2 = new IntegerOption.Definition(31, "Q-Block-2", false, 0, 3);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc8613.html#section-2"
	 *      target= "_blank">RFC8613 2. The OSCORE Option</a>
	 */
	public static final OpaqueOption.Definition OSCORE = new OpaqueOption.Definition(OptionNumberRegistry.OSCORE,
			Names.Object_Security, true, 0, 255);
	/**
	 * Not supported for now, only for logging!
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc9175.html#section-2.2.1"
	 *      target= "_blank">RFC9175 2.2.1. Echo Option Format</a>
	 * @since 3.9
	 */
	public static final OpaqueOption.Definition ECHO = new OpaqueOption.Definition(252, "Echo", true, 1, 40);
	/**
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7967.html#section-2"
	 *      target= "_blank">RFC7967 2. Option Definition</a>
	 */
	public static final NoResponseOption.Definition NO_RESPONSE = new NoResponseOption.Definition();
	/**
	 * Not supported for now, only for logging!
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc9175.html#section-3.2.1"
	 *      target= "_blank">RFC9175 3.2.1. Request-Tag Option Format </a>
	 * @since 3.9
	 */
	public static final OpaqueOption.Definition REQUEST_TAG = new OpaqueOption.Definition(292, "Request-Tag", false, 0,
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
