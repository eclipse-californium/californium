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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add OMA LWM2M content types
 *    Achim Kraus (Bosch Software Innovations GmbH) - add OMA LWM2M 1.1 content types
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;


/**
 * This class describes the CoAP Media Type Registry as defined in
 * RFC 7252, Section 12.3.
 */
public class MediaTypeRegistry {

	// Constants ///////////////////////////////////////////////////////////////
	public static final int TEXT_PLAIN = 0;
	public static final int APPLICATION_LINK_FORMAT = 40;
	public static final int APPLICATION_XML = 41;
	public static final int APPLICATION_OCTET_STREAM = 42;
	public static final int APPLICATION_XMPP_XML = 46;
	public static final int APPLICATION_EXI = 47;
	public static final int APPLICATION_JSON = 50; // 04
	public static final int APPLICATION_CBOR = 60;
	public static final int APPLICATION_SENML_JSON = 110;
	public static final int APPLICATION_SENML_CBOR = 112;
	public static final int APPLICATION_VND_OMA_LWM2M_TLV = 11542;
	public static final int APPLICATION_VND_OMA_LWM2M_JSON = 11543;
	public static final int MAX_TYPE = 0xffff;
	
	// implementation specific
	public static final int UNDEFINED = -1;

	// initializer
	private static final HashMap<Integer, String[]> registry = new HashMap<Integer, String[]>();
	static {
		add(UNDEFINED, "unknown", "???");

		add(TEXT_PLAIN, "text/plain", "txt");

		add(APPLICATION_LINK_FORMAT, "application/link-format", "wlnk");
		add(APPLICATION_XML, "application/xml", "xml");
		add(APPLICATION_OCTET_STREAM, "application/octet-stream", "bin");
		add(APPLICATION_XMPP_XML, "application/xmpp+xml", "xmpp");
		add(APPLICATION_EXI, "application/exi", "exi");
		add(APPLICATION_JSON, "application/json", "json");
		add(APPLICATION_CBOR, "application/cbor", "cbor"); // RFC 7049
		add(APPLICATION_SENML_JSON, "application/senml+json", "json");
		add(APPLICATION_SENML_CBOR, "application/senml+cbor", "cbor"); // RFC 7049
		add(APPLICATION_VND_OMA_LWM2M_TLV, "application/vnd.oma.lwm2m+tlv", "tlv");
		add(APPLICATION_VND_OMA_LWM2M_JSON, "application/vnd.oma.lwm2m+json", "json");
	}

	// Static Functions ////////////////////////////////////////////////////////

	public static Set<Integer> getAllMediaTypes() {
		return registry.keySet();
	}

	public static boolean isPrintable(int mediaType) {
		switch (mediaType) {
		case TEXT_PLAIN:
		case APPLICATION_LINK_FORMAT:
		case APPLICATION_XML:
		case APPLICATION_XMPP_XML:
		case APPLICATION_JSON:
		case APPLICATION_SENML_JSON:
		case APPLICATION_VND_OMA_LWM2M_JSON:

		case UNDEFINED:
			return true;

		case APPLICATION_OCTET_STREAM:
		case APPLICATION_EXI:
		case APPLICATION_CBOR:
		case APPLICATION_SENML_CBOR:
		case APPLICATION_VND_OMA_LWM2M_TLV:
		default:
			return false;
		}
	}

	public static int parse(String type) {
		if (type == null) {
			return UNDEFINED;
		}

		for (Integer key : registry.keySet()) {
			if (registry.get(key)[0].equalsIgnoreCase(type)) {
				return key;
			}
		}

		return UNDEFINED;
	}

	public static Integer[] parseWildcard(String regex) {
		regex = regex.trim().substring(0, regex.indexOf('*')).trim().concat(".*");
		Pattern pattern = Pattern.compile(regex);
		List<Integer> matches = new LinkedList<Integer>();

		for (Integer mediaType : registry.keySet()) {
			String mime = registry.get(mediaType)[0];
			if (pattern.matcher(mime).matches()) {
				matches.add(mediaType);
			}
		}

		return matches.toArray(new Integer[0]);
	}

	public static String toFileExtension(int mediaType) {
		String texts[] = registry.get(mediaType);

		if (texts != null) {
			return texts[1];
		} else {
			return "unknown_" + mediaType;
		}
	}

	public static String toString(int mediaType) {
		if (mediaType == UNDEFINED){
			return "undefined";
		}

		String texts[] = registry.get(mediaType);
		if (texts != null) {
			return texts[0];
		} else {
			return "unknown/" + mediaType;
		}
	}

	private static void add(int mediaType, String string, String extension) {
		registry.put(mediaType, new String[] { string, extension });
	}
}
