/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import org.eclipse.californium.core.coap.option.OptionDefinition;
import org.eclipse.californium.core.coap.option.OptionRegistry;

/**
 * This class describes the CoAP Option Number Registry as defined in RFC 7252,
 * Section 12.2 and other CoAP extensions.
 * 
 * <a href=
 * "https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#option-numbers">
 * IANA - CoAP Option Numbers</a>.
 * 
 * Since 3.8 {@link OptionDefinition} and {@link OptionRegistry} is introduced
 * and is the preferred and future way to specify, which option is represented.
 * The option number on it's own represents this only for the traditional
 * options, but options introduced with
 * <a href="https://www.rfc-editor.org/rfc/rfc8323#section-5.2" target=
 * "_blank"> RFC8323 5.2. Signaling Option Numbers</a> options dependent also on
 * the message code.
 */
public final class OptionNumberRegistry {
	public static final int UNKNOWN			= -1;

	// RFC 7252
	public static final int RESERVED_0		= 0;
	public static final int IF_MATCH		= 1;
	public static final int URI_HOST		= 3;
	public static final int ETAG			= 4;
	public static final int IF_NONE_MATCH	= 5;
	public static final int URI_PORT		= 7;
	public static final int LOCATION_PATH	= 8;
	public static final int URI_PATH		= 11;
	public static final int CONTENT_FORMAT	= 12;
	public static final int MAX_AGE			= 14;
	public static final int URI_QUERY		= 15;
	public static final int ACCEPT			= 17;
	public static final int LOCATION_QUERY	= 20;
	public static final int PROXY_URI		= 35;
	public static final int PROXY_SCHEME	= 39;
	public static final int SIZE1			= 60;
	public static final int RESERVED_1		= 128;
	public static final int RESERVED_2		= 132;
	public static final int RESERVED_3		= 136;
	public static final int RESERVED_4		= 140;

	// RFC 7641
	public static final int OBSERVE			= 6;

	// RFC 7959
	public static final int BLOCK2			= 23;
	public static final int BLOCK1			= 27;
	public static final int SIZE2			= 28;

	// RFC 8613
	public static final int OSCORE			= 9;

	// RFC 7967
	public static final int NO_RESPONSE		= 258;

	/**
	 * Option names.
	 */
	public static class Names {
		public static final String Reserved			= "Reserved";

		public static final String If_Match			= "If-Match";
		public static final String Uri_Host			= "Uri-Host";
		public static final String ETag				= "ETag";
		public static final String If_None_Match	= "If-None-Match";
		public static final String Uri_Port			= "Uri-Port";
		public static final String Location_Path	= "Location-Path";
		public static final String Uri_Path			= "Uri-Path";
		public static final String Content_Format	= "Content-Format";
		public static final String Max_Age			= "Max-Age";
		public static final String Uri_Query		= "Uri-Query";
		public static final String Accept			= "Accept";
		public static final String Location_Query	= "Location-Query";
		public static final String Proxy_Uri		= "Proxy-Uri";
		public static final String Proxy_Scheme		= "Proxy-Scheme";
		public static final String Size1			= "Size1";

		public static final String Observe			= "Observe";

		public static final String Block2			= "Block2";
		public static final String Block1			= "Block1";
		public static final String Size2			= "Size2";

		public static final String Object_Security	= "Object-Security";

		public static final String No_Response		= "No-Response";
	}

	/**
	 * Option default values.
	 */
	public static class Defaults {
		
		/** The default Max-Age. */
		public static final long MAX_AGE = 60L;
	}

	/**
	 * The format types of CoAP options.
	 */
	public static enum OptionFormat {
		INTEGER, STRING, OPAQUE, UNKNOWN, EMPTY
	}

	/**
	 * Checks whether an option is critical.
	 * 
	 * @param optionNumber
	 *            The option number to check
	 * @return {@code true} if the option is critical
	 */
	public static boolean isCritical(int optionNumber) {
		return (optionNumber & 1) != 0;
	}

	/**
	 * Checks whether an option is elective.
	 * 
	 * @param optionNumber
	 *            The option number to check
	 * @return {@code true} if the option is elective
	 */
	public static boolean isElective(int optionNumber) {
		return (optionNumber & 1) == 0;
	}

	/**
	 * Checks whether an option is unsafe.
	 * 
	 * @param optionNumber
	 *            The option number to check
	 * @return {@code true} if the option is unsafe
	 */
	public static boolean isUnsafe(int optionNumber) {
		// When bit 6 is 1, an option is Unsafe
		return (optionNumber & 2) > 0;
	}

	/**
	 * Checks whether an option is safe.
	 * 
	 * @param optionNumber
	 *            The option number to check
	 * @return {@code true} if the option is safe
	 */
	public static boolean isSafe(int optionNumber) {
		return !isUnsafe(optionNumber);
	}

	/**
	 * Checks whether an option is not a cache-key.
	 * 
	 * @param optionNumber
	 *            The option number to check
	 * @return {@code true} if the option is not a cache-key
	 */
	public static boolean isNoCacheKey(int optionNumber) {
		/*
		 * When an option is not Unsafe, it is not a Cache-Key (NoCacheKey) if
		 * and only if bits 3-5 are all set to 1; all other bit combinations
		 * mean that it indeed is a Cache-Key
		 * 
		 * https://tools.ietf.org/html/rfc7252#page-40
		 * 
		 * Critical = (onum & 1);
		 * UnSafe = (onum & 2);
		 * NoCacheKey = ((onum & 0x1e) == 0x1c);
		 * 
		 *    Figure 11: Determining Characteristics from an Option Number
		 */
		return (optionNumber & 0x1E) == 0x1C;
	}

	/**
	 * Checks whether an option is a cache-key.
	 * 
	 * @param optionNumber
	 *            The option number to check
	 * @return {@code true} if the option is a cache-key
	 */
	public static boolean isCacheKey(int optionNumber) {
		return !isNoCacheKey(optionNumber);
	}

	/**
	 * Checks if is uri option.
	 * 
	 * @param optionNumber
	 *            the option number
	 * @return {@code true} if is uri option
	 */
	public static boolean isUriOption(int optionNumber) {
		boolean result = optionNumber == URI_HOST || optionNumber == URI_PATH || optionNumber == URI_PORT || optionNumber == URI_QUERY;
		return result;
	}

	private OptionNumberRegistry() {
	}
}
