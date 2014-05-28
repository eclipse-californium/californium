/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.coap;


/**
 * CoAP defines several constants.
 * <ul>
 * <li>Message types: CON, NON, ACK, RST</li>
 * <li>Request codes: GET, POST, PUT, DELETE</li>
 * <li>Response codes</li>
 * <li>Option numbers</li>
 * <li>Message format</li>
 * </ul>
 * @see MediaTypeRegistry
 */
public class CoAP {
	
	public static final int VERSION = 0x01;
	
	public static final String COAP_URI_SCHEME = "coap";
	public static final String COAP_SECURE_URI_SCHEME = "coaps";
	
	private CoAP() {
		// prevent initialization
	}
	
	/**
	 * CoAP defines four types of messages: Confirmable, Non-confirmable,
	 * Acknowledgment, Reset;.
	 */
	public enum Type {
		
		/** The Confirmable. */
		CON(0),

		/** The Non-confirmable. */
		NON(1),
		
		/** The Acknowledgment */
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
		public static Type valueOf(int value) {
			switch (value) {
				case 0: return CON;
				case 1: return NON;
				case 2: return ACK;
				case 3: return RST;
				default: throw new IllegalArgumentException("Unknown CoAP type "+value);
			}
		}
	}
	
	/**
	 * The enumeration of request codes: GET, POST; PUT and DELETE.
	 */
	public enum Code {
		
		/** The GET code. */
		GET(1),

		/** The POST code. */
		POST(2),
		
		/** The PUT code. */
		PUT(3),
		
		/** The DELETE code. */
		DELETE(4);
		
		/** The code value. */
		public final int value;
		
		/**
		 * Instantiates a new code with the specified code value.
		 *
		 * @param value the integer value of the code
		 */
		Code(int value) {
			this.value = value;
		}
		
		/**
		 * Converts the specified integer value to a request code.
		 *
		 * @param value the integer value
		 * @return the request code
		 * @throws IllegalArgumentException if the integer value is unrecognized
		 */
		public static Code valueOf(int value) {
			switch (value) {
				case 1: return GET;
				case 2: return POST;
				case 3: return PUT;
				case 4: return DELETE;
				default: throw new IllegalArgumentException("Unknwon CoAP request code "+value);
			}
		}
	}
	
	/**
	 * The enumeration of response codes
	 */
	public enum ResponseCode {
		
		// Success
		CREATED(65),
		DELETED(66),
		VALID(67),
		CHANGED(68),
		CONTENT(69),
		CONTINUE(95),

		// Client error
		BAD_REQUEST(128),
		UNAUTHORIZED(129),
		BAD_OPTION(130),
		FORBIDDEN(131),
		NOT_FOUND(132),
		METHOD_NOT_ALLOWED(133),
		NOT_ACCEPTABLE(134),
		REQUEST_ENTITY_INCOMPLETE(136),
		PRECONDITION_FAILED(140),
		REQUEST_ENTITY_TOO_LARGE(141), 
		UNSUPPORTED_CONTENT_FORMAT(143),

		// Server error
		INTERNAL_SERVER_ERROR(160),
		NOT_IMPLEMENTED(161),
		BAD_GATEWAY(162),
		SERVICE_UNAVAILABLE(163),
		GATEWAY_TIMEOUT(164),
		PROXY_NOT_SUPPORTED(165);
		
		/** The code value. */
		public final int value;
		
		/**
		 * Instantiates a new response code with the specified integer value.
		 *
		 * @param value the integer value
		 */
		private ResponseCode(int value) {
			this.value = value;
		}
		
		/**
		 * Converts the specified integer value to a response code.
		 *
		 * @param value the value
		 * @return the response code
		 * @throws IllegalArgumentException if integer value is not recognized
		 */
		public static ResponseCode valueOf(int value) {
			switch (value) {
				case 65: return CREATED;
				case 66: return DELETED;
				case 67: return VALID;
				case 68: return CHANGED;
				case 69: return CONTENT;
				case 128: return BAD_REQUEST;
				case 129: return UNAUTHORIZED;
				case 130: return BAD_OPTION;
				case 131: return FORBIDDEN;
				case 132: return NOT_FOUND;
				case 133: return METHOD_NOT_ALLOWED;
				case 134: return NOT_ACCEPTABLE;
				case 136: return REQUEST_ENTITY_INCOMPLETE;
				case 140: return PRECONDITION_FAILED;
				case 141: return REQUEST_ENTITY_TOO_LARGE;
				case 143: return UNSUPPORTED_CONTENT_FORMAT;
				case 160: return INTERNAL_SERVER_ERROR;
				case 161: return NOT_IMPLEMENTED;
				case 162: return BAD_GATEWAY;
				case 163: return SERVICE_UNAVAILABLE;
				case 164: return GATEWAY_TIMEOUT;
				case 165: return PROXY_NOT_SUPPORTED;
				default: // Make an extensive search
					for (ResponseCode code:ResponseCode.values())
						if (code.value == value) return code;
					throw new IllegalArgumentException("Unknown CoAP response code "+value);
			}
		}
		
		public String toString() {
			return String.format("%d.%02d", this.value/32, this.value%32);
		}
		
		public static boolean isSuccess(ResponseCode code) {
			return 65 <= code.value && code.value <= 127;
		}
		
		public static boolean isClientError(ResponseCode code) {
			return BAD_REQUEST.value <= code.value && code.value < INTERNAL_SERVER_ERROR.value;
		}
		
		public static boolean isServerError(ResponseCode code) {
			return INTERNAL_SERVER_ERROR.value <= code.value;
		}
	}

	/**
	 * CoAP Option Number Registry.
	 */
	public static class OptionRegistry {
		
		// draft-ietf-core-coap-14
		public static final int RESERVED_0 =      0;
		public static final int IF_MATCH =        1;
		public static final int URI_HOST =        3;
		public static final int ETAG =            4;
		public static final int IF_NONE_MATCH =   5;
		public static final int URI_PORT =        7;
		public static final int LOCATION_PATH =   8;
		public static final int URI_PATH =       11;
		public static final int CONTENT_FORMAT = 12;
		public static final int MAX_AGE =        14;
		public static final int URI_QUERY =      15;
		public static final int ACCEPT =         17;
		public static final int LOCATION_QUERY = 20;
		public static final int PROXY_URI =      35;
		public static final int PROXY_SCHEME =   39;
		public static final int RESERVED_1 =    128;
		public static final int RESERVED_2 =    132;
		public static final int RESERVED_3 =    136;
		public static final int RESERVED_4 =    140;

		// draft-ietf-core-observe-08
		public static final int OBSERVE = 6;
	
		// draft-ietf-core-block-10
		public static final int BLOCK2 = 23;
		public static final int BLOCK1 = 27;
		public static final int SIZE =   28;
		
		/**
		 * Option Number Registry default values.
		 */
		public static class Default {
			
			/** The default MAX_AGE. */
			public static final long MAX_AGE = 60L;
		}
	}
	
	/**
	 * CoAP message format.
	 */
	public class MessageFormat {
		
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
		public static final int EMPTY_CODE = 0;
		
		/** The lowest value of a request code. */
		public static final int REQUEST_CODE_LOWER_BOUND = 1;
		
		/** The highest value of a request code. */
		public static final int REQUEST_CODE_UPPER_BOUNT = 31;
		
		/** The lowest value of a response code. */
		public static final int RESPONSE_CODE_LOWER_BOUND = 64;
		
		/** The highest value of a response code. */
		public static final int RESPONSE_CODE_UPPER_BOUND = 191;
	}
}
