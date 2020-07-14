/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Bosch Software Innovations GmbH - improve readability
 *    Achim Kraus (Bosch Software Innovations GmbH) - add getDefaultPort
 *                                                    add CodeClass
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce protocols
 *                                                    with mapping to schemes
 *    Achim Kraus (Bosch Software Innovations GmbH) - add IPv4 multicast address
 *    Achim Kraus (Bosch Software Innovations GmbH) - add IPATCH and TOO_MANY_REQUESTS
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.elements.util.StandardCharsets;

/**
 * CoAP defines several constants.
 * <ul>
 * <li>Message types: CON, NON, ACK, RST</li>
 * <li>Request codes: GET, POST, PUT, DELETE, FETCH, PATCH, IPATCH, (CUSTOM_30)</li>
 * <li>Response codes</li>
 * <li>Option numbers</li>
 * <li>Message format</li>
 * </ul>
 * @see OptionNumberRegistry
 * @see MediaTypeRegistry
 */
public final class CoAP {

	/** RFC 7252 CoAP version */
	public static final int VERSION = 0x01;

	/** The UDP protocol */
	public static final String PROTOCOL_UDP = "UDP";

	/** The DTLS protocol */
	public static final String PROTOCOL_DTLS = "DTLS";
	
	/** The TCP protocol */
	public static final String PROTOCOL_TCP = "TCP";

	/** The TLS protocol */
	public static final String PROTOCOL_TLS = "TLS";

	/** The CoAP URI scheme */
	public static final String COAP_URI_SCHEME = "coap";

	/** The CoAP URI scheme */
	public static final String COAP_TCP_URI_SCHEME = "coap+tcp";

	/** The CoAP URI scheme */
	public static final String COAP_SECURE_TCP_URI_SCHEME = "coaps+tcp";

	/** The CoAPS URI scheme */
	public static final String COAP_SECURE_URI_SCHEME = "coaps";

	/**
	 * The URI scheme separator
	 * 
	 * @since 2.4
	 */
	public static final String URI_SCHEME_SEPARATOR = "://";

	/** The default CoAP port for normal CoAP communication (coap) */
	public static final int DEFAULT_COAP_PORT = 5683;

	/** The default CoAP port for secure CoAP communication (coaps) */
	public static final int DEFAULT_COAP_SECURE_PORT = 5684;

	/** The CoAP charset is always UTF-8 */
	public static final Charset UTF8_CHARSET = StandardCharsets.UTF_8;

	/** IPv4 multicast address for CoAP, RFC 7252, 12.8. */
	public static final InetAddress MULTICAST_IPV4 = new InetSocketAddress("224.0.1.187", 0).getAddress();
	/**
	 * IPv6 multicast address for CoAP, RFC 7252, 12.8., FF0X::FD, link-local.
	 * See <a href="https://tools.ietf.org/html/rfc7346#section-2">RFC7346, IPv6 Multicast Address Scopes</a> 
	 */
	public static final InetAddress MULTICAST_IPV6_LINKLOCAL = new InetSocketAddress("[FF02::FD]", 0).getAddress();
	/**
	 * IPv6 multicast address for CoAP, RFC 7252, 12.8., FF0X::FD, site-local.
	 * See <a href="https://tools.ietf.org/html/rfc7346#section-2">RFC7346, IPv6 Multicast Address Scopes</a> 
	 */
	public static final InetAddress MULTICAST_IPV6_SITELOCAL = new InetSocketAddress("[FF05::FD]", 0).getAddress();

	private static final Map<String, Code> codeMap = new HashMap<>();
	private static final Map<String, ResponseCode> responseCodeMap = new HashMap<>();

	private CoAP() {
		// prevent instantiation
	}

	/**
	 * Gets the code class of a given CoAP code.
	 * 
	 * @param code the code.
	 * @return the value represented by the three most significant bits of the code.
	 */
	public static int getCodeClass(final int code) {
		return (code & 0b11100000) >> 5;
	}

	/**
	 * Gets the code detail of a given CoAP code.
	 * 
	 * @param code the code.
	 * @return the value represented by the five least significant bits of the code.
	 */
	public static int getCodeDetail(final int code) {
		return code & 0b00011111;
	}

	/**
	 * Gets the string representation of a CoAP code.
	 * 
	 * @param code the CoAP code.
	 * @return a string following the pattern C.DD where C is the code class nd DD is the code detail.
	 */
	public static String formatCode(final int code) {
		return formatCode(getCodeClass(code), getCodeDetail(code));
	}

	private static String formatCode(final int codeClass, final int codeDetail) {
		return String.format("%d.%02d", codeClass, codeDetail);
	}

	/**
	 * Get scheme for protocol.
	 * 
	 * @param protocol protocol
	 * @return scheme
	 * @throws IllegalArgumentException if protocol is not supported
	 */
	public static String getSchemeForProtocol(final String protocol) {
		if (PROTOCOL_UDP.equalsIgnoreCase(protocol)) {
			return COAP_URI_SCHEME;
		} else if (PROTOCOL_DTLS.equalsIgnoreCase(protocol)) {
			return COAP_SECURE_URI_SCHEME;
		} else if (PROTOCOL_TCP.equalsIgnoreCase(protocol)) {
			return COAP_TCP_URI_SCHEME;
		} else if (PROTOCOL_TLS.equalsIgnoreCase(protocol)) {
			return COAP_SECURE_TCP_URI_SCHEME;
		}
		throw new IllegalArgumentException("Protocol " + protocol + " not supported!");
	}

	/**
	 * Get protocol for scheme.
	 * 
	 * @param scheme scheme
	 * @return protocol
	 * @throws IllegalArgumentException if scheme is not supported
	 * @since 2.4
	 */
	public static String getProtocolForScheme(final String scheme) {
		if (COAP_URI_SCHEME.equalsIgnoreCase(scheme)) {
			return PROTOCOL_UDP;
		} else if (COAP_SECURE_URI_SCHEME.equalsIgnoreCase(scheme)) {
			return PROTOCOL_DTLS;
		} else if (COAP_TCP_URI_SCHEME.equalsIgnoreCase(scheme)) {
			return PROTOCOL_TCP;
		} else if (COAP_SECURE_TCP_URI_SCHEME.equalsIgnoreCase(scheme)) {
			return PROTOCOL_TLS;
		}
		throw new IllegalArgumentException("Scheme " + scheme + " not supported!");
	}

	/**
	 * Checks, if provided protocol is {@link #PROTOCOL_TCP} or {@link #PROTOCOL_TLS}.
	 * 
	 * @param protocol protocol to be checked
	 * @return true, if the provided protocol matchs one of the list above, false, otherwise.
	 */
	public static boolean isTcpProtocol(final String protocol) {
		return PROTOCOL_TCP.equalsIgnoreCase(protocol)
				|| PROTOCOL_TLS.equalsIgnoreCase(protocol);
	}

	/**
	 * Checks, if provided protocol is {@link #PROTOCOL_DTLS} or {@link #PROTOCOL_TLS}.
	 * 
	 * @param protocol protocol to be checked
	 * @return true, if the provided protocol matchs one of the list above, false, otherwise.
	 */
	public static boolean isSecureProtocol(final String protocol) {
		return PROTOCOL_DTLS.equalsIgnoreCase(protocol)
				|| PROTOCOL_TLS.equalsIgnoreCase(protocol);
	}

	/**
	 * Checks, if provided scheme is {@link #COAP_TCP_URI_SCHEME} or {@link #COAP_SECURE_TCP_URI_SCHEME}.
	 * 
	 * @param uriScheme scheme to be checked
	 * @return true, if the provided scheme match one of the list above, false, otherwise.
	 */
	public static boolean isTcpScheme(final String uriScheme) {
		return COAP_TCP_URI_SCHEME.equalsIgnoreCase(uriScheme)
				|| COAP_SECURE_TCP_URI_SCHEME.equalsIgnoreCase(uriScheme);
	}

	/**
	 * Checks, if provided scheme is {@link #COAP_SECURE_URI_SCHEME} or {@link #COAP_SECURE_TCP_URI_SCHEME}.
	 * 
	 * @param uriScheme scheme to be checked
	 * @return true, if the provided scheme match one of the list above, false, otherwise.
	 */
	public static boolean isSecureScheme(final String uriScheme) {
		return COAP_SECURE_URI_SCHEME.equalsIgnoreCase(uriScheme)
				|| COAP_SECURE_TCP_URI_SCHEME.equalsIgnoreCase(uriScheme);
	}

	/**
	 * Checks, if provided scheme is {@link #COAP_URI_SCHEME}, {@link #COAP_SECURE_URI_SCHEME}, {@link #COAP_TCP_URI_SCHEME} or {@link #COAP_SECURE_TCP_URI_SCHEME}.
	 * 
	 * @param uriScheme scheme to be checked
	 * @return true, if the provided scheme match one of the list above, false, otherwise.
	 */
	public static boolean isSupportedScheme(final String uriScheme) {
		return CoAP.COAP_URI_SCHEME.equalsIgnoreCase(uriScheme) ||
				CoAP.COAP_TCP_URI_SCHEME.equalsIgnoreCase(uriScheme) ||
				CoAP.COAP_SECURE_URI_SCHEME.equalsIgnoreCase(uriScheme) ||
				CoAP.COAP_SECURE_TCP_URI_SCHEME.equalsIgnoreCase(uriScheme);
	}
	
	/**
	 * Get default port for provided uri scheme.
	 * 
	 * @param uriScheme uri scheme for default port
	 * @return default port
	 * @throws IllegalArgumentException if provided uri scheme is not supported.
	 * @see #DEFAULT_COAP_PORT
	 * @see #DEFAULT_COAP_SECURE_PORT
	 */
	public static int getDefaultPort(final String uriScheme) {
		if (CoAP.COAP_URI_SCHEME.equalsIgnoreCase(uriScheme)) {
			return DEFAULT_COAP_PORT;
		} else if (CoAP.COAP_SECURE_URI_SCHEME.equalsIgnoreCase(uriScheme)) {
			return DEFAULT_COAP_SECURE_PORT;
		} else if (CoAP.COAP_TCP_URI_SCHEME.equalsIgnoreCase(uriScheme)) {
			return DEFAULT_COAP_PORT;
		} else if (CoAP.COAP_SECURE_TCP_URI_SCHEME.equalsIgnoreCase(uriScheme)) {
			/*
			 * This may be changed to 443. But depending on the availability of
			 * "Application-Layer Protocol Negotiation Extension" (ALPN)
			 * [RFC7301], currently 5684 seems to be the better choice.
			 */
			return DEFAULT_COAP_SECURE_PORT;
		}
		throw new IllegalArgumentException("URI scheme '" + uriScheme + "' is not supported!");
	}

	/**
	 * Get scheme from URI.
	 * 
	 * Simple implementation searching for {@link #URI_SCHEME_SEPARATOR} and
	 * returns the URI up to that, when found.
	 * 
	 * @param uri uri
	 * @return scheme, or {@code null}, if not contained.
	 * @since 2.4
	 */
	public static String getSchemeFromUri(final String uri) {
		int index = uri.indexOf(URI_SCHEME_SEPARATOR);
		if (index > 0) {
			return uri.substring(0, index);
		}
		return null;
	}

	/**
	 * Checks if a given CoAP code is a request code.
	 * 
	 * @param code the code to check.
	 * @return {@code true} if the code's class is 0 and 1 &lt;= detail &lt;= 31.
	 */
	public static boolean isRequest(final int code) {
		return code >= REQUEST_CODE_LOWER_BOUND &&
				code <= REQUEST_CODE_UPPER_BOUND;
	}

	/**
	 * Checks if a given CoAP code is a response code.
	 * 
	 * @param code the code to check.
	 * @return {@code true} if 1 &lt; code class &lt;6 and 0 &lt;= detail &lt;= 31.
	 */
	public static boolean isResponse(final int code) {
		return code >= RESPONSE_CODE_LOWER_BOUND &&
				code <= RESPONSE_CODE_UPPER_BOUND;
	}

	/**
	 * Checks if a given CoAP code is the <em>empty message</em> code.
	 * 
	 * @param code the code to check.
	 * @return {@code true} if code == 0.
	 */
	public static boolean isEmptyMessage(final int code) {
		return code == EMPTY_CODE;
	}

	/**
	 * Checks if a given CoAP code is a observable method.
	 * 
	 * @param code the code to check.
	 * @return {@code true} if code is GET or FETCH.
	 */
	public static boolean isObservable(final Code code) {
		return code == Code.GET || code == Code.FETCH;
	}

	/**
	 * CoAP defines four types of messages:
	 * Confirmable, Non-confirmable, Acknowledgment, Reset.
	 */
	public enum Type {

		/** The Confirmable. */
		CON(0),

		/** The Non-confirmable. */
		NON(1),

		/** The Acknowledgment. */
		ACK(2),

		/** The Reject. */
		RST(3);

		/** The integer value of a message type. */
		public final int value;

		/**
		 * Instantiates a new type with the specified integer value.
		 *
		 * @param value the integer value
		 */
		Type(int value) {
			this.value = value;
		}

		/**
		 * Converts an integer into its corresponding message type.
		 *
		 * @param value the integer value
		 * @return the message type
		 * @throws IllegalArgumentException if the integer value is unrecognized
		 */
		public static Type valueOf(final int value) {
			switch (value) {
				case 0: return CON;
				case 1: return NON;
				case 2: return ACK;
				case 3: return RST;
				default: throw new IllegalArgumentException("Unknown CoAP type " + value);
			}
		}
	}

	/**
	 * The enumeration of request codes: GET, POST, PUT and DELETE.
	 */
	public enum CodeClass {

		/** The request class code. */
		REQUEST(0),

		/** The successful response class code. */
		SUCCESS_RESPONSE(2),

		/** The error response class code. */
		ERROR_RESPONSE(4),

		/** The server error response class code. */
		SERVER_ERROR_RESPONSE(5),
		
		/** The signaling  class code. */
		SIGNAL(7);

		/** The code value. */
		public final int value;

		/**
		 * Instantiates a new code with the specified code value.
		 *
		 * @param value the integer value of the code
		 */
		private CodeClass(final int value) {
			this.value = value;
		}

		/**
		 * Converts the specified integer value to a request code.
		 *
		 * @param value the integer value
		 * @return the request code
		 * @throws MessageFormatException if the integer value does not represent a valid request code.
		 */
		public static CodeClass valueOf(final int value) {
			switch (value) {
				case 0: return REQUEST;
				case 2: return SUCCESS_RESPONSE;
				case 4: return ERROR_RESPONSE;
				case 5: return SERVER_ERROR_RESPONSE;
				case 7: return SIGNAL;
				default: throw new MessageFormatException(String.format("Unknown CoAP class code: %d", value));
			}
		}
	}

	/**
	 * The enumeration of request codes: GET, POST, PUT, DELETE, FETCH, PATCH, IPATCH, and CUSTOM_30.
	 */
	public enum Code {

		/** The GET code. */
		GET(1),

		/** The POST code. */
		POST(2),

		/** The PUT code. */
		PUT(3),

		/** The DELETE code. */
		DELETE(4),
		
		/** The FETCH code. */
		FETCH(5),
		
		/** The PATCH code. */
		PATCH(6),

		/** The IPATCH code. */
		IPATCH(7),

		/** 
		 * The custom code 30.
		 * 
		 * Support for openHAB custom CoAP extension, CoIoT, used for shelly binding.
		 * <a href="https://shelly-api-docs.shelly.cloud/images/CoIoT%20for%20Shelly%20devices%20(rev%201.0)%20.pdf">CoIot Shelly</a>.
		 * 
		 * Note: though this code is not assigned byt IANA, it may cause future incompatibilities.
		 * If the IANA assigns this value, this will get replaced!
		 * <a href="https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#method-codes">IANA CoAP Codes</a>.
		 */
		CUSTOM_30(30);

		/** The code value. */
		public final int value;
		/** 
		 * The code value in textual format. "0.dd"
		 * @since 2.1
		 */
		public final String text;

		/**
		 * Instantiates a new code with the specified code value.
		 *
		 * @param value the integer value of the code
		 */
		private Code(final int value) {
			this.value = value;
			this.text = formatCode(getCodeClass(value), getCodeDetail(value));
			codeMap.put(text, this);
		}

		/**
		 * Converts the specified integer value to a request code.
		 *
		 * @param value the integer value
		 * @return the request code
		 * @throws MessageFormatException if the integer value does not represent a valid request code.
		 */
		public static Code valueOf(final int value) {
			int codeClass = getCodeClass(value);
			int codeDetail = getCodeDetail(value);
			if (codeClass > 0) {
				throw new MessageFormatException(String.format("Not a CoAP request code: %s", formatCode(codeClass, codeDetail)));
			}
			switch (codeDetail) {
				case 1: return GET;
				case 2: return POST;
				case 3: return PUT;
				case 4: return DELETE;
				case 5: return FETCH;
				case 6: return PATCH;
				case 7: return IPATCH;
				case 30: return CUSTOM_30;
				default: throw new MessageFormatException(String.format("Unknown CoAP request code: %s", formatCode(codeClass, codeDetail)));
			}
		}

		/**
		 * Converts the specified textual value to a request code.
		 *
		 * @param value textual value of format "0.dd".
		 * @return the request code. {@code null}, if textual value doesn't
		 *         match a request code.
		 * @since 2.1
		 */
		public static Code valueOfText(String value) {
			return codeMap.get(value);
		}

	}

	/**
	 * The enumeration of response codes
	 */
	public enum ResponseCode {
		
		// Success: 2.01 - 2.31
		_UNKNOWN_SUCCESS_CODE(CodeClass.SUCCESS_RESPONSE, 0), // undefined -- only used to identify class
		CREATED(CodeClass.SUCCESS_RESPONSE, 1),
		DELETED(CodeClass.SUCCESS_RESPONSE, 2),
		VALID(CodeClass.SUCCESS_RESPONSE, 3),
		CHANGED(CodeClass.SUCCESS_RESPONSE, 4),
		CONTENT(CodeClass.SUCCESS_RESPONSE, 5),
		CONTINUE(CodeClass.SUCCESS_RESPONSE, 31),

		// Client error: 4.00 - 4.31
		BAD_REQUEST(CodeClass.ERROR_RESPONSE, 0),
		UNAUTHORIZED(CodeClass.ERROR_RESPONSE, 1),
		BAD_OPTION(CodeClass.ERROR_RESPONSE, 2),
		FORBIDDEN(CodeClass.ERROR_RESPONSE, 3),
		NOT_FOUND(CodeClass.ERROR_RESPONSE, 4),
		METHOD_NOT_ALLOWED(CodeClass.ERROR_RESPONSE, 5),
		NOT_ACCEPTABLE(CodeClass.ERROR_RESPONSE, 6),
		REQUEST_ENTITY_INCOMPLETE(CodeClass.ERROR_RESPONSE, 8),
		CONFLICT(CodeClass.ERROR_RESPONSE, 9),
		PRECONDITION_FAILED(CodeClass.ERROR_RESPONSE, 12),
		REQUEST_ENTITY_TOO_LARGE(CodeClass.ERROR_RESPONSE, 13),
		UNSUPPORTED_CONTENT_FORMAT(CodeClass.ERROR_RESPONSE, 15),
		UNPROCESSABLE_ENTITY(CodeClass.ERROR_RESPONSE, 22),
		TOO_MANY_REQUESTS(CodeClass.ERROR_RESPONSE, 29),

		// Server error: 5.00 - 5.31
		INTERNAL_SERVER_ERROR(CodeClass.SERVER_ERROR_RESPONSE, 0),
		NOT_IMPLEMENTED(CodeClass.SERVER_ERROR_RESPONSE, 1),
		BAD_GATEWAY(CodeClass.SERVER_ERROR_RESPONSE, 2),
		SERVICE_UNAVAILABLE(CodeClass.SERVER_ERROR_RESPONSE, 3),
		GATEWAY_TIMEOUT(CodeClass.SERVER_ERROR_RESPONSE, 4),
		PROXY_NOT_SUPPORTED(CodeClass.SERVER_ERROR_RESPONSE, 5);

		/** The code value. */
		public final int value;
		public final int codeClass;
		public final int codeDetail;
		/** 
		 * The code value in textual format. "c.dd"
		 * @since 2.1
		 */
		public final String text;

		/**
		 * Instantiates a new response code with the specified integer value.
		 *
		 * @param value the integer value
		 */
		private ResponseCode(final CodeClass codeClass, final int codeDetail) {
			this.codeClass = codeClass.value;
			this.codeDetail = codeDetail;
			this.value = codeClass.value << 5 | codeDetail;
			this.text = formatCode(codeClass.value, codeDetail);
			responseCodeMap.put(text, this);
		}

		/**
		 * Converts the specified integer value to a response code.
		 *
		 * @param value the value
		 * @return the response code
		 * @throws MessageFormatException if the value does not represent a valid response code.
		 */
		public static ResponseCode valueOf(final int value) {
			int codeClass = getCodeClass(value);
			int codeDetail = getCodeDetail(value);
			switch (codeClass) {
			case 2:
				return valueOfSuccessCode(codeDetail);
			case 4:
				return valueOfClientErrorCode(codeDetail);
			case 5:
				return valueOfServerErrorCode(codeDetail);
			default:
				throw new MessageFormatException(String.format("Not a CoAP response code: %s", formatCode(codeClass, codeDetail)));
			}
		}

		/**
		 * Converts the specified textual value to a response code.
		 *
		 * @param value textual value of format "c.dd".
		 * @return the response code. {@code null}, if textual value doesn't
		 *         match a response code.
		 * @since 2.1
		 */
		public static ResponseCode valueOfText(String value) {
			return responseCodeMap.get(value);
		}

		private static ResponseCode valueOfSuccessCode(final int codeDetail) {
			switch(codeDetail) {
			case 1: return CREATED;
			case 2: return DELETED;
			case 3: return VALID;
			case 4: return CHANGED;
			case 5: return CONTENT;
			case 31: return CONTINUE;
			default:
				return _UNKNOWN_SUCCESS_CODE;
			}
		}

		private static ResponseCode valueOfClientErrorCode(final int codeDetail) {
			switch(codeDetail) {
			case 0: return BAD_REQUEST;
			case 1: return UNAUTHORIZED;
			case 2: return BAD_OPTION;
			case 3: return FORBIDDEN;
			case 4: return NOT_FOUND;
			case 5: return METHOD_NOT_ALLOWED;
			case 6: return NOT_ACCEPTABLE;
			case 8: return REQUEST_ENTITY_INCOMPLETE;
			case 9: return CONFLICT;
			case 12: return PRECONDITION_FAILED;
			case 13: return REQUEST_ENTITY_TOO_LARGE;
			case 15: return UNSUPPORTED_CONTENT_FORMAT;
			case 22: return UNPROCESSABLE_ENTITY;
			case 29: return TOO_MANY_REQUESTS;
			default:
				return BAD_REQUEST;
			}
		}

		private static ResponseCode valueOfServerErrorCode(final int codeDetail) {
			switch(codeDetail) {
			case 0: return INTERNAL_SERVER_ERROR;
			case 1: return NOT_IMPLEMENTED;
			case 2: return BAD_GATEWAY;
			case 3: return SERVICE_UNAVAILABLE;
			case 4: return GATEWAY_TIMEOUT;
			case 5: return PROXY_NOT_SUPPORTED;
			default:
				return INTERNAL_SERVER_ERROR;
			}
		}

		@Override
		public String toString() {
			return text;
		}

		/**
		 * Checks if a response code indicates success.
		 * 
		 * @param code The response code to check.
		 * @return {@code true} if the given code's class is {@link CodeClass#SUCCESS_RESPONSE}).
		 * @throws NullPointerException if the code is {@code null}.
		 */
		public static boolean isSuccess(final ResponseCode code) {
			if (null == code) {
				throw new NullPointerException("ResponseCode must not be null!");
			}
			return code.codeClass == CodeClass.SUCCESS_RESPONSE.value;
		}

		/**
		 * Checks if a response code indicates a client error.
		 * 
		 * @param code The response code to check.
		 * @return {@code true} if the given code's class is {@link CodeClass#ERROR_RESPONSE}).
		 * @throws NullPointerException if the code is {@code null}.
		 */
		public static boolean isClientError(final ResponseCode code) {
			if (null == code) {
				throw new NullPointerException("ResponseCode must not be null!");
			}
			return code.codeClass == CodeClass.ERROR_RESPONSE.value;
		}

		/**
		 * Checks if a response code indicates a server error.
		 * 
		 * @param code The response code to check.
		 * @return {@code true} if the given code's class is {@link CodeClass#SERVER_ERROR_RESPONSE}).
		 * @throws NullPointerException if the code is {@code null}.
		 */
		public static boolean isServerError(final ResponseCode code) {
			if (null == code) {
				throw new NullPointerException("ResponseCode must not be null!");
			}
			return code.codeClass == CodeClass.SERVER_ERROR_RESPONSE.value;
		}
	}

	/**
	 * CoAP message format.
	 */
	public final class MessageFormat {
		/** The length of len nibble when running in TCP mode. */
		public static final int LENGTH_NIBBLE_BITS = 4;

		/** number of bits used for the encoding of the CoAP version field. */
		public static final int VERSION_BITS     = 2;

		/** number of bits used for the encoding of the message type field. */
		public static final int TYPE_BITS        = 2;

		/** number of bits used for the encoding of the token length field. */
		public static final int TOKEN_LENGTH_BITS = 4;

		/** number of bits used for the encoding of the request method/response code field. */
		public static final int CODE_BITS = 8;

		/** number of bits used for the encoding of the message ID. */
		public static final int MESSAGE_ID_BITS = 16;

		/** number of bits used for the encoding of the option delta field. */
		public static final int OPTION_DELTA_BITS = 4;

		/** number of bits used for the encoding of the option delta field. */
		public static final int OPTION_LENGTH_BITS = 4;

		/** One byte which indicates indicates the end of options and the start of the payload. */
		public static final byte PAYLOAD_MARKER = (byte) 0xFF;

		/** CoAP version supported by this Californium version. */
		public static final int VERSION = 1;

		/** The code value of an empty message. */
		public static final int EMPTY_CODE = 0b00000000; // 0.00

		/** The lowest value of a request code. */
		public static final int REQUEST_CODE_LOWER_BOUND = 0b00000001; // 0.01

		/** The highest value of a request code. */
		public static final int REQUEST_CODE_UPPER_BOUND = 0b00011111; // 0.31

		/** The lowest value of a response code. */
		public static final int RESPONSE_CODE_LOWER_BOUND = 0b01000000; // 2.00

		/** The highest value of a response code. */
		public static final int RESPONSE_CODE_UPPER_BOUND = 0b10111111; // 5.31

		private MessageFormat() {
			// prevent instantiation
		}
	}
}
