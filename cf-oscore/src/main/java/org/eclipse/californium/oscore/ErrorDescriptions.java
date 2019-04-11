/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

/**
 * 
 * Central location for all potential error messages
 *
 */
public final class ErrorDescriptions {

	public static final String CONTEXT_NOT_FOUND = ("Security context not found");
	public static final String FAILED_TO_DECODE_COSE = ("Failed to decode COSE");
	public static final String REPLAY_DETECT = ("Replay detected");
	public static final String DECRYPTION_FAILED = ("Decryption failed");
	public static final String MAC_CCM_FAILED = ("MAC check in CCM failed");
	public static final String TOKEN_NULL = ("Token is null");
	public static final String TOKEN_INVALID = ("Token is invalid");
	public static final String SEQ_NBR_INVALID = ("Sequence number is invalid");
	public static final String URI_NULL = ("URI is null");
	public static final String DB_NULL = ("DB is null");
	public static final String CTX_NULL = ("Context is null");
	public static final String TYPE_NULL = ("Type is null");
	public static final String UNEXPECTED_OBSERVE = ("Unexpected observe option");
	public static final String SOURCE_ADRESS_NULL = ("Source address is null");
	public static final String SOURCE_PORT_NULL = ("Source port is null");
	public static final String SOURCE_PORT_INVALID = ("Source port is invalid");
	public static final String ERROR_MESS_NULL = ("Error message is null");
	public static final String MID_INVALID = ("MID is invalid");
	public static final String MISSING_KID = ("KID is missing");
	public static final String EXCEPTION_NULL = ("Exception is null");
	public static final String REQUEST_NULL = ("Request is null");
	public static final String OPTIONSET_NULL = ("OptionSet is null");
	public static final String WRONG_VERSION_NBR = ("Wrong version number");
	public static final String BYTE_ARRAY_NULL = ("Byte array is null");
	public static final String NONCE_FAILED = ("Nonce generation failed");
	public static final String PARTIAL_IV_NULL = ("PartialIV is null");
	public static final String SENDER_ID_NULL = ("SenderID is null");
	public static final String COMMON_IV_NULL = ("CommonIV is null");
	public static final String NONCE_LENGTH_INVALID = ("Nonce length is invalid");
	public static final String COAP_CODE_INVALID = ("Coap Code is invalid");
	public static final String ILLEGAL_PAYLOAD_MARKED = "Payload marker found with zero-length payload";
	public static final String STRING_NULL = "String is null";
	public static final String CONTEXT_NULL = "Context is null";
	public static final String ALGORITHM_NOT_DEFINED = "Algorithm not defined";

	public static final String CANNOT_CREATE_ERROR_MESS = ("Cannot create error message for this error");

	private ErrorDescriptions() {
	}
}
