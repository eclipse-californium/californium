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
package org.eclipse.californium.core.network.serialization;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.CODE_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.EMPTY_CODE;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.MESSAGE_ID_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.PAYLOAD_MARKER;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.REQUEST_CODE_LOWER_BOUND;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.REQUEST_CODE_UPPER_BOUNT;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.RESPONSE_CODE_LOWER_BOUND;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.RESPONSE_CODE_UPPER_BOUND;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.TOKEN_LENGTH_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.TYPE_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.VERSION_BITS;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;

/**
 * The DataParser parses incoming byte arrays to messages.
 */
public class DataParser {

	private DatagramReader reader;
	
	private int version;
	private int type;
	private int tokenlength;
	private int code;
	private int mid;
	
	public DataParser(byte[] bytes) {
		setBytes(bytes);
	}
	
	public void setBytes(byte[] bytes) {
		this.reader = new DatagramReader(bytes);
		this.version = reader.read(VERSION_BITS);
		this.type = reader.read(TYPE_BITS);
		this.tokenlength = reader.read(TOKEN_LENGTH_BITS);
		this.code = reader.read(CODE_BITS);
		this.mid = reader.read(MESSAGE_ID_BITS);
	}
	
	public boolean isWellFormed() {
		return version == CoAP.VERSION;
	}
	
	public int getVersion() {
		return version;
	}
	
	public int getMID() {
		return mid;
	}
	
	public boolean isReply() {
		return type > CoAP.Type.NON.value;
	}
	
	public boolean isRequest() {
		return code >= REQUEST_CODE_LOWER_BOUND &&
				code <= REQUEST_CODE_UPPER_BOUNT;
	}
	
	public boolean isResponse() {
		return code >= RESPONSE_CODE_LOWER_BOUND &&
				code <= RESPONSE_CODE_UPPER_BOUND;
	}
	
	public boolean isEmpty() {
		return code == EMPTY_CODE;
	}
	
	public Request parseRequest() {
		assert(isRequest());
		Request request = new Request(Code.valueOf(code));
		parseMessage(request);
		return request;
	}
	
	public Response parseResponse() {
		assert(isResponse());
		Response response = new Response(ResponseCode.valueOf(code));
		parseMessage(response);
		return response;
	}
	
	public EmptyMessage parseEmptyMessage() {
		assert(!isRequest() && !isResponse());
		EmptyMessage message = new EmptyMessage(Type.valueOf(type));
		parseMessage(message);
		return message;
	}
	
	private void parseMessage(Message message) {
		message.setType(Type.valueOf(type));
		message.setMID(mid);		
		
		if (tokenlength>0) {
			message.setToken(reader.readBytes(tokenlength));
		} else {
			message.setToken(new byte[0]);
		}
		
		int currentOption = 0;
		byte nextByte = 0;
		while(reader.bytesAvailable()) {
			nextByte = reader.readNextByte();
			if (nextByte != PAYLOAD_MARKER) {
				// the first 4 bits of the byte represent the option delta
				int optionDeltaNibble = (0xF0 & nextByte) >> 4;
				currentOption += readOptionValueFromNibble(optionDeltaNibble);
				
				// the second 4 bits represent the option length
				int optionLengthNibble = (0x0F & nextByte);
				int optionLength = readOptionValueFromNibble(optionLengthNibble);
				
				// read option
				Option option = new Option(currentOption);
				option.setValue(reader.readBytes(optionLength));
				
				// add option to message
				addOptionToSet(option, message.getOptions());
			} else break;
		}
		
		if (nextByte == PAYLOAD_MARKER) {
			// the presence of a marker followed by a zero-length payload must be processed as a message format error
			if (!reader.bytesAvailable())
				throw new IllegalStateException();
			
			// get payload
			message.setPayload(reader.readBytesLeft());
		} else {
			message.setPayload(new byte[0]); // or null?
		}
	}
	
	// TODO: Can we optimize this a little by not creating new option objects for known options
	private void addOptionToSet(Option option, OptionSet optionSet) {
		switch (option.getNumber()) {
			case CoAP.OptionRegistry.IF_MATCH:       optionSet.addIfMatch(option.getValue()); break;
			case CoAP.OptionRegistry.URI_HOST:       optionSet.setURIHost(option.getStringValue()); break;
			case CoAP.OptionRegistry.ETAG:           optionSet.addETag(option.getValue()); break;
			case CoAP.OptionRegistry.IF_NONE_MATCH:  optionSet.setIfNoneMatch(true); break;
			case CoAP.OptionRegistry.URI_PORT:       optionSet.setURIPort(option.getIntegerValue()); break;
			case CoAP.OptionRegistry.LOCATION_PATH:  optionSet.addLocationPath(option.getStringValue()); break;
			case CoAP.OptionRegistry.URI_PATH:       optionSet.addURIPath(option.getStringValue()); break;
			case CoAP.OptionRegistry.CONTENT_FORMAT: optionSet.setContentFormat(option.getIntegerValue()); break;
			case CoAP.OptionRegistry.MAX_AGE:        optionSet.setMaxAge(option.getLongValue()); break;
			case CoAP.OptionRegistry.URI_QUERY:      optionSet.addURIQuery(option.getStringValue()); break;
			case CoAP.OptionRegistry.ACCEPT:         optionSet.setAccept(option.getIntegerValue()); break;
			case CoAP.OptionRegistry.LOCATION_QUERY: optionSet.addLocationQuery(option.getStringValue()); break;
			case CoAP.OptionRegistry.PROXY_URI:      optionSet.setProxyURI(option.getStringValue()); break;
			case CoAP.OptionRegistry.PROXY_SCHEME:   optionSet.setProxyScheme(option.getStringValue()); break;
			case CoAP.OptionRegistry.BLOCK1:         optionSet.setBlock1(option.getValue()); break;
			case CoAP.OptionRegistry.BLOCK2:         optionSet.setBlock2(option.getValue()); break;
			case CoAP.OptionRegistry.OBSERVE:        optionSet.setObserve(option.getIntegerValue()); break;
			default: optionSet.addOption(option);
		}
	}
	
	/**
	 * Calculates the value used in the extended option fields as specified in
	 * draft-ietf-core-coap-14, section 3.1
	 * 
	 * @param nibble
	 *            the 4-bit option header value.
	 * @param datagram
	 *            the datagram.
	 * @return the value calculated from the nibble and the extended option
	 *         value.
	 */
	private int readOptionValueFromNibble(int nibble) {
		if (nibble <= 12) {
			return nibble;
		} else if (nibble == 13) {
			return reader.read(8) + 13;
		} else if (nibble == 14) {
			return reader.read(16) + 269;
		} else {
			throw new IllegalArgumentException("Unsupported option delta "+nibble);
		}
	}
}
