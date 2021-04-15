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

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * This class describes the CoAP Media Type Registry as defined in RFC 7252,
 * Section 12.3.
 * 
 * @see <a href=
 *      "https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats"
 *      target="_top">IANA - CoAP Content-Formats</a>
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
	private static final Map<Integer, MediaTypeDefintion> registry = new ConcurrentHashMap<>();

	static {

		addPrintable(TEXT_PLAIN, "text/plain", "txt", true);

		addPrintable(APPLICATION_LINK_FORMAT, "application/link-format", "wlnk", false);
		// charset is defined in xml itself.
		// Changing it requires to adapt it in xml as well.
		addPrintable(APPLICATION_XML, "application/xml", "xml", false);
		addNonePrintable(APPLICATION_OCTET_STREAM, "application/octet-stream", "bin");
		addPrintable(APPLICATION_XMPP_XML, "application/xmpp+xml", "xmpp", false);
		addNonePrintable(APPLICATION_EXI, "application/exi", "exi");
		addPrintable(APPLICATION_JSON, "application/json", "json", false);
		// RFC 7049
		addNonePrintable(APPLICATION_CBOR, "application/cbor", "cbor");
		addPrintable(APPLICATION_SENML_JSON, "application/senml+json", "json", false);
		// RFC 7049
		addNonePrintable(APPLICATION_SENML_CBOR, "application/senml+cbor", "cbor");
		addNonePrintable(APPLICATION_VND_OMA_LWM2M_TLV, "application/vnd.oma.lwm2m+tlv", "tlv");
		addPrintable(APPLICATION_VND_OMA_LWM2M_JSON, "application/vnd.oma.lwm2m+json", "json", false);
	}

	// Static Functions ////////////////////////////////////////////////////////

	/**
	 * Get all registered media-types.
	 * 
	 * @return set of media types.
	 */
	public static Set<Integer> getAllMediaTypes() {
		return registry.keySet();
	}

	/**
	 * Get media-type-definition.
	 * 
	 * @param mediaType coap-media-type
	 * @return media-type-definition, or {@code null}, if not available.
	 * @since 3.0
	 */
	public static MediaTypeDefintion getDefinition(int mediaType) {
		return registry.get(mediaType);
	}

	/**
	 * Check, if media type is known.
	 * 
	 * @param mediaType media type to check.
	 * @return {@code true}, if known, or {@code false}, otherwise.
	 * @since 3.0
	 */
	public static boolean isKnown(int mediaType) {
		return registry.containsKey(mediaType);
	}

	/**
	 * Check, if media type is printable.
	 * 
	 * @param mediaType media type to check.
	 * @return {@code true}, if printable, or {@code false}, otherwise.
	 */
	public static boolean isPrintable(int mediaType) {
		MediaTypeDefintion definition = registry.get(mediaType);
		if (definition != null) {
			return definition.isPrintable();
		} else {
			return false;
		}
	}

	/**
	 * Check, if media type uses a convertible charset.
	 * 
	 * CoAP only supports UTF-8 textual payload. If coap-payload is going the be
	 * converted (e.g. for a coap-http-cross-proxy), it may be important, if the
	 * charset is also convertible. For some media types (e.g. xml), the charset
	 * is encoded in the payload itself. For other media types it's not
	 * recommended (e.g. JSON). For these, it's not possible to adapt the
	 * charset and therefore these media types are registered with as not
	 * convertible.
	 * 
	 * @param mediaType media type to check.
	 * @return {@code true}, if the charset is convertible, or {@code false},
	 *         otherwise.
	 * @since 3.0
	 */
	public static boolean isCharsetConvertible(int mediaType) {
		MediaTypeDefintion definition = registry.get(mediaType);
		if (definition != null) {
			return definition.isCharsetConvertible();
		} else {
			return false;
		}
	}

	/**
	 * Parse the media type string.
	 * 
	 * @param type media type string
	 * @return media type
	 */
	public static int parse(String type) {
		if (type == null) {
			return UNDEFINED;
		}

		for (MediaTypeDefintion defintion : registry.values()) {
			if (defintion.match(type)) {
				return defintion.getType();
			}
		}

		return UNDEFINED;
	}

	/**
	 * Parse the media type string supporting wildcards.
	 * 
	 * @param wildcard media type string with optional wildcards
	 * @return set of media types (without {@link #UNDEFINED}).
	 * @since 3.0 (changed return type from Integer[] to int[])
	 */
	public static int[] parseWildcard(String wildcard) {
		List<Integer> matches = new LinkedList<Integer>();
		if (wildcard.equals("*/*")) {
			for (MediaTypeDefintion defintion : registry.values()) {
				matches.add(defintion.getType());
			}
		} else if (wildcard.endsWith("/*")) {
			Pattern pattern = Pattern.compile(wildcard.replace("*", ".*"));
			for (MediaTypeDefintion defintion : registry.values()) {
				if (defintion.match(pattern)) {
					matches.add(defintion.getType());
				}
			}
		} else {
			for (MediaTypeDefintion defintion : registry.values()) {
				if (defintion.match(wildcard)) {
					matches.add(defintion.getType());
				}
			}
		}
		int[] result = new int[matches.size()];
		for (int index=0; index < result.length;++index) {
			result[index] = matches.get(index);
		}
		return result;
	}

	/**
	 * Get file extension for media type.
	 * 
	 * @param mediaType media type
	 * @return file extension, or "unknown_nnn".
	 */
	public static String toFileExtension(int mediaType) {
		MediaTypeDefintion definition = registry.get(mediaType);
		if (definition != null) {
			return definition.getFileExtension();
		} else {
			return "unknown_" + mediaType;
		}
	}

	/**
	 * Get mime for media type.
	 * 
	 * @param mediaType media type
	 * @return mime, "undefined", or "unknown/nnn".
	 */
	public static String toString(int mediaType) {
		if (mediaType == UNDEFINED) {
			return "undefined";
		}

		MediaTypeDefintion definition = registry.get(mediaType);
		if (definition != null) {
			return definition.getMime();
		} else {
			return "unknown/" + mediaType;
		}
	}

	/**
	 * Create a none printable media-type-definition.
	 * 
	 * @param mediaType media-type
	 * @param mime mime
	 * @param extension file extension
	 * @since 3.0
	 */
	private static void addNonePrintable(int mediaType, String mime, String extension) {
		add(new MediaTypeDefintion(mediaType, mime, extension));
	}

	/**
	 * Create a printable media-type-definition.
	 * 
	 * @param mediaType media-type
	 * @param mime mime
	 * @param extension file extension
	 * @param isCharsetConvertible {@code true}, if the charset may be
	 *            converted, {@code false}, otherwise.
	 * @since 3.0
	 */
	private static void addPrintable(int mediaType, String mime, String extension, boolean isCharsetConvertible) {
		add(new MediaTypeDefintion(mediaType, mime, extension, isCharsetConvertible));
	}

	/**
	 * Add a media-type-definition.
	 * 
	 * @param definition media-type-definition to add
	 * @since 3.0
	 */
	public static void add(MediaTypeDefintion definition) {
		registry.put(definition.getType(), definition);
	}

	/**
	 * Media type definition.
	 * 
	 * @since 3.0
	 */
	public static class MediaTypeDefintion {

		/**
		 * CoAP media type according IANA.
		 */
		private final Integer type;
		/**
		 * MIME name.
		 */
		private final String mime;
		/**
		 * File extension.
		 */
		private final String fileExtension;
		/**
		 * Printable indicator.
		 */
		private final boolean isPrintable;
		/**
		 * Convertible charset indicator.
		 */
		private final boolean isCharsetConvertible;

		/**
		 * Create none-printable media-type-definition.
		 * 
		 * @param type IANA CoAP media type
		 * @param mime MIME name
		 * @param fileExtension file extension
		 * @throws NullPointerException if one of the provided arguments is
		 *             {@code null}
		 */
		public MediaTypeDefintion(Integer type, String mime, String fileExtension) {
			if (type == null) {
				throw new NullPointerException("type must not be null!");
			}
			if (mime == null) {
				throw new NullPointerException("mime must not be null!");
			}
			if (fileExtension == null) {
				throw new NullPointerException("file extension must not be null!");
			}
			this.type = type;
			this.mime = mime;
			this.fileExtension = fileExtension;
			this.isPrintable = false;
			this.isCharsetConvertible = false;
		}

		/**
		 * Create none-printable media-type-definition.
		 * 
		 * @param type IANA CoAP media type
		 * @param mime MIME name
		 * @param fileExtension file extension
		 * @param isCharsetConvertible {@code true}, if the charset may be
		 *            converted, {@code false}, otherwise.
		 * @throws NullPointerException if one of the provided arguments is
		 *             {@code null}
		 */
		public MediaTypeDefintion(Integer type, String mime, String fileExtension, boolean isCharsetConvertible) {
			if (type == null) {
				throw new NullPointerException("type must not be null!");
			}
			if (mime == null) {
				throw new NullPointerException("mime must not be null!");
			}
			if (fileExtension == null) {
				throw new NullPointerException("file extension must not be null!");
			}
			this.type = type;
			this.mime = mime;
			this.fileExtension = fileExtension;
			this.isPrintable = true;
			this.isCharsetConvertible = isCharsetConvertible;
		}

		/**
		 * Match the mime type.
		 * 
		 * @param mime mime type to match
		 * @return {@code true}, if matching, {@code false}, otherwise.
		 */
		public boolean match(String mime) {
			return this.mime.equalsIgnoreCase(mime);
		}

		/**
		 * Match the mime type.
		 * 
		 * @param mimePattern mime type pattern to match
		 * @return {@code true}, if matching, {@code false}, otherwise.
		 */
		public boolean match(Pattern mimePattern) {
			return mimePattern.matcher(mime).matches();
		}

		/**
		 * Get CoAP media type according IANA
		 * 
		 * @return media type
		 */
		public Integer getType() {
			return type;
		}

		/**
		 * GET MIME.
		 * 
		 * @return mime
		 */
		public String getMime() {
			return mime;
		}

		/**
		 * Get file extension.
		 * 
		 * @return file extension
		 */
		public String getFileExtension() {
			return fileExtension;
		}

		/**
		 * Check, if media-type is printable.
		 * 
		 * @return {@code true}, if the media-type is printable, {@code false},
		 *         otherwise.
		 */
		public boolean isPrintable() {
			return isPrintable;
		}

		/**
		 * Check, if charset is convertible.
		 * 
		 * @return {@code true}, if the charset may be converted, {@code false},
		 *         otherwise.
		 */
		public boolean isCharsetConvertible() {
			return isCharsetConvertible;
		}
	}
}
