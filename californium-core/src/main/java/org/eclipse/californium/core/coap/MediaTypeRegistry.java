/*******************************************************************************
 * Copyright (c) 2015, 2021 Institute for Pervasive Computing, ETH Zurich and others.
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

import java.util.Arrays;
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
	public static final int APPLICATION_COSE_ENCRYPT0 = 16;
	public static final int APPLICATION_COSE_MAC0 = 17;
	public static final int APPLICATION_COSE_SIGN1 = 18;
	public static final int APPLICATION_ACE_CBOR = 19;
	public static final int IMAGE_GIF = 21;
	public static final int IMAGE_JPEG = 22;
	public static final int IMAGE_PNG = 23;
	public static final int APPLICATION_LINK_FORMAT = 40;
	public static final int APPLICATION_XML = 41;
	public static final int APPLICATION_OCTET_STREAM = 42;
	public static final int APPLICATION_XMPP_XML = 46;
	public static final int APPLICATION_EXI = 47;
	public static final int APPLICATION_JSON = 50; // 04
	public static final int APPLICATION_JSON_PATCH = 51;
	public static final int APPLICATION_MERGE_PATCH = 52;
	public static final int APPLICATION_CBOR = 60;
	public static final int APPLICATION_CWT = 61;
	public static final int APPLICATION_MULTIPART_CORE = 62;
	public static final int APPLICATION_CBOR_SEQ = 63;
	public static final int APPLICATION_COSE_ENCRYPT = 96;
	public static final int APPLICATION_COSE_MAC = 97;
	public static final int APPLICATION_COSE_SIGN = 98;
	public static final int APPLICATION_COSE_KEY = 101;
	public static final int APPLICATION_COSE_KEY_SET = 102;
	public static final int APPLICATION_SENML_JSON = 110;
	public static final int APPLICATION_SENSML_JSON = 111;
	public static final int APPLICATION_SENML_CBOR = 112;
	public static final int APPLICATION_SENSML_CBOR = 113;
	public static final int APPLICATION_SENML_EXI = 114;
	public static final int APPLICATION_SENSML_EXI = 115;
	public static final int APPLICATION_COAP_GROUP = 256;
	public static final int APPLICATION_DOTS_CBOR = 271;
	public static final int APPLICATION_MISSING_BLOCKS_CBOR_SEQ = 272;
	public static final int APPLICATION_PKCS7_SERVER_GENERATED_KEY = 280;
	public static final int APPLICATION_PKCS7_CERTS_ONLY = 281;
	public static final int APPLICATION_PKCS8 = 284;
	public static final int APPLICATION_CSATTRS = 285;
	public static final int APPLICATION_PKCS10 = 286;
	public static final int APPLICATION_PKIX_CERT = 287;
	public static final int APPLICATION_SENML_XML = 310;
	public static final int APPLICATION_SENSML_XML = 311;
	public static final int APPLICATION_SENML_ETCH_JSON = 320;
	public static final int APPLICATION_SENML_ETCH_CBOR = 322;
	public static final int APPLICATION_TD_JSON = 432;
	public static final int APPLICATION_VND_OCF_CBOR = 10000;
	public static final int APPLICATION_OSCORE = 10001;
	public static final int APPLICATION_JAVASCRIPT = 10002;
	public static final int APPLICATION_VND_OMA_LWM2M_TLV = 11542;
	public static final int APPLICATION_VND_OMA_LWM2M_JSON = 11543;
	public static final int APPLICATION_VND_OMA_LWM2M_CBOR = 11544;
	public static final int TEXT_CSS = 20000;
	public static final int IMAGE_SVG_XML = 30000;
	public static final int MAX_TYPE = 0xffff;

	// implementation specific
	public static final int UNDEFINED = -1;

	private static final int[] EMPTY = new int[0];

	// initializer
	private static final Map<Integer, MediaTypeDefintion> registry = new ConcurrentHashMap<>();

	static {

		addPrintable(TEXT_PLAIN, "text/plain", "txt", true);

		addNonPrintable(APPLICATION_COSE_ENCRYPT0, "application/cose; cose-type=\"cose-encrypt0\"", "cbor");
		addNonPrintable(APPLICATION_COSE_MAC0, "application/cose; cose-type=\"cose-mac0\"", "cbor");
		addNonPrintable(APPLICATION_COSE_SIGN1, "application/cose; cose-type=\"cose-sign1\"", "cbor");

		addNonPrintable(APPLICATION_ACE_CBOR, "application/ace+cbor", "cbor");

		addNonPrintable(IMAGE_GIF, "image/gif", "gif");
		addNonPrintable(IMAGE_JPEG, "image/jpeg", "jpeg");
		addNonPrintable(IMAGE_PNG, "image/png", "png");

		addPrintable(APPLICATION_LINK_FORMAT, "application/link-format", "wlnk", false);
		// charset is defined in xml itself.
		// Changing it requires to adapt it in xml as well.
		addPrintable(APPLICATION_XML, "application/xml", "xml", false);
		addNonPrintable(APPLICATION_OCTET_STREAM, "application/octet-stream", "bin");
		addPrintable(APPLICATION_XMPP_XML, "application/xmpp+xml", "xmpp", false);
		addNonPrintable(APPLICATION_EXI, "application/exi", "exi");
		addPrintable(APPLICATION_JSON, "application/json", "json", false);
		addPrintable(APPLICATION_JSON_PATCH, "application/json-patch+json", "json", false);
		addPrintable(APPLICATION_MERGE_PATCH, "application/merge-patch+json", "json", false);
		// RFC 7049
		addNonPrintable(APPLICATION_CBOR, "application/cbor", "cbor");
		addNonPrintable(APPLICATION_CWT, "application/cwt", "cwt");
		addNonPrintable(APPLICATION_MULTIPART_CORE, "application/multipart-core", "part");
		addNonPrintable(APPLICATION_CBOR_SEQ, "application/cbor-seq", "cbor");

		addNonPrintable(APPLICATION_COSE_ENCRYPT, "application/cose; cose-type=\"cose-encrypt\"", "cbor");
		addNonPrintable(APPLICATION_COSE_MAC, "application/cose; cose-type=\"cose-mac\"", "cbor");
		addNonPrintable(APPLICATION_COSE_SIGN, "application/cose; cose-type=\"cose-sign\"", "cbor");
		addNonPrintable(APPLICATION_COSE_KEY, "application/cose-key", "cbor");
		addNonPrintable(APPLICATION_COSE_KEY_SET, "application/cose-key-set", "cbor");

		addPrintable(APPLICATION_SENML_JSON, "application/senml+json", "json", false);
		addPrintable(APPLICATION_SENSML_JSON, "application/sensml+json", "json", false);
		// RFC 7049
		addNonPrintable(APPLICATION_SENML_CBOR, "application/senml+cbor", "cbor");
		addNonPrintable(APPLICATION_SENSML_CBOR, "application/sensml+cbor", "cbor");
		addNonPrintable(APPLICATION_SENML_EXI, "application/senml+exi", "exi");
		addNonPrintable(APPLICATION_SENSML_EXI, "application/sensml+exi", "exi");

		addPrintable(APPLICATION_COAP_GROUP, "application/coap-group+json", "json", false);

		addNonPrintable(APPLICATION_DOTS_CBOR, "application/dots+cbor", "cbor");
		addNonPrintable(APPLICATION_MISSING_BLOCKS_CBOR_SEQ, "application/missing-blocks+cbor-seq", "cbor");

		addNonPrintable(APPLICATION_PKCS7_SERVER_GENERATED_KEY,
				"application/pkcs7-mime; smime-type=\"server-generated-key\"", "pkcs");
		addNonPrintable(APPLICATION_PKCS7_CERTS_ONLY, "application/pkcs7-mime; smime-type=\"certs-only\"", "pkcs");
		addNonPrintable(APPLICATION_PKCS8, "application/pkcs8", "pkcs");
		addNonPrintable(APPLICATION_CSATTRS, "application/csattrs", "csattrs");
		addNonPrintable(APPLICATION_PKCS10, "application/pkcs10", "pkcs");
		addNonPrintable(APPLICATION_PKIX_CERT, "application/pkix-cert", "pkix");

		addPrintable(APPLICATION_SENML_XML, "application/senml+xml", "xml", false);
		addPrintable(APPLICATION_SENSML_XML, "application/sensml+xml", "xml", false);
		addPrintable(APPLICATION_SENML_ETCH_JSON, "application/senml-etch+json", "json", false);
		addNonPrintable(APPLICATION_SENML_ETCH_CBOR, "application/senml-etch+cbor", "cbor");

		addPrintable(APPLICATION_TD_JSON, "application/td+json", "json", false);

		addNonPrintable(APPLICATION_VND_OCF_CBOR, "application/vnd.ocf+cbor", "cbor");
		addNonPrintable(APPLICATION_OSCORE, "application/oscore", "oscore");
		addPrintable(APPLICATION_JAVASCRIPT, "application/javascript", "js", false);

		addNonPrintable(APPLICATION_VND_OMA_LWM2M_TLV, "application/vnd.oma.lwm2m+tlv", "tlv");
		addPrintable(APPLICATION_VND_OMA_LWM2M_JSON, "application/vnd.oma.lwm2m+json", "json", false);
		addNonPrintable(APPLICATION_VND_OMA_LWM2M_CBOR, "application/vnd.oma.lwm2m+cbor", "cbor");

		addPrintable(TEXT_CSS, "text/css", "css", false);

		addPrintable(IMAGE_SVG_XML, "image/svg+xml", "xml", false);
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
	 * Parse the media type string with mime parameter.
	 * 
	 * @param mime media type string, may contain a mime parameter
	 * @return set of media types (without {@link #UNDEFINED}).
	 * @throws NullPointerException if mimeType is {@code null}
	 * @since 3.10
	 */
	public static int[] parseWithParameter(String mime) {
		String[] mimeDefinition = parseMime(mime);
		List<Integer> matches = new LinkedList<Integer>();
		for (MediaTypeDefintion defintion : registry.values()) {
			if (defintion.match(mimeDefinition[0], mimeDefinition[1])) {
				matches.add(defintion.getType());
			}
		}
		return toArray(matches);
	}

	/**
	 * Parse the media type string supporting wildcards.
	 * 
	 * @param wildcard media type string with optional wildcards
	 * @return set of media types (without {@link #UNDEFINED}).
	 * @throws NullPointerException if wildcard is {@code null}
	 * @since 3.0 (changed return type from {@code Integer[]} to {@code int[]})
	 */
	public static int[] parseWildcard(String wildcard) {
		if (wildcard == null) {
			throw new NullPointerException("wildcard must not be null!");
		}
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
		return toArray(matches);
	}

	/**
	 * Parse mime content type.
	 * 
	 * @param mime mime content type
	 * @return array of strings, mime type at position 0, mime parameter at
	 *         position 1.
	 * @throws NullPointerException if mime is {@code null}
	 * @since 3.10
	 */
	public static String[] parseMime(String mime) {
		if (mime == null) {
			throw new NullPointerException("mime must not be null!");
		}
		String[] result = new String[2];
		String[] split = mime.split(";", 2);
		for (int index = 0; index < split.length; ++index) {
			result[index] = split[index].trim();
			if (result[index].isEmpty()) {
				result[index] = null;
			}
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
	 * Convert list of {@link Integer} into array of {@code int}s.
	 * 
	 * @param value list of {@link Integer} values.
	 * @return array of {@code int}s
	 * @since 3.10
	 */
	private static int[] toArray(List<Integer> value) {
		if (value.isEmpty()) {
			return EMPTY;
		}
		int[] result = new int[value.size()];
		for (int index = 0; index < result.length; ++index) {
			result[index] = value.get(index);
		}
		Arrays.sort(result);
		return result;
	}

	/**
	 * Create a non-printable media-type-definition.
	 * 
	 * @param mediaType media-type
	 * @param mime mime
	 * @param extension file extension
	 * @since 3.0
	 */
	private static void addNonPrintable(int mediaType, String mime, String extension) {
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
		 * MIME type.
		 * 
		 * @since 3.10
		 */
		private final String mimeType;
		/**
		 * MIME parameter.
		 * 
		 * @since 3.10
		 */
		private final String mimeParameter;
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
			String[] parts = parseMime(mime);
			this.mimeType = parts[0];
			this.mimeParameter = parts[1];
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
			String[] parts = parseMime(mime);
			this.mimeType = parts[0];
			this.mimeParameter = parts[1];
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
		 * @param mimeType mime type to match
		 * @param mimeParameter mime parameter to match
		 * @return {@code true}, if matching, {@code false}, otherwise.
		 * @since 3.10
		 */
		public boolean match(String mimeType, String mimeParameter) {
			if (!this.mimeType.equalsIgnoreCase(mimeType)) {
				return false;
			}
			if (this.mimeParameter == null || mimeParameter == null) {
				return true;
			}
			return this.mimeParameter.equalsIgnoreCase(mimeParameter);
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
