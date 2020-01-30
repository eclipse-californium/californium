/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - derived from org.eclipse.californium.proxy
 ******************************************************************************/
package org.eclipse.californium.proxy2;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.OptionNumberRegistry;

/**
 * This class maps different protocol constants for the Cf cross-proxy.
 */
public class MappingProperties extends Properties {

	private static final Logger LOG = LoggerFactory.getLogger(MappingProperties.class);

	/**
	 * auto-generated to eliminate warning
	 */
	private static final long serialVersionUID = 4126898261482584755L;

	/** The header for Californium property files. */
	private static final String HEADER = "Californium Cross-Proxy2 mapping properties file";

	private static final String KEY_COAP_METHOD = "coap.request.code.";
	private static final String KEY_COAP_CODE = "coap.response.code.";
	public static final String KEY_COAP_OPTION = "coap.message.option.";
	public static final String KEY_COAP_MEDIA = "coap.message.media.";
	private static final String KEY_HTTP_CODE = "http.response.code.";
	private static final String KEY_HTTP_METHOD = "http.request.method.";
	public static final String KEY_HTTP_HEADER = "http.message.header.";
	public static final String KEY_HTTP_CONTENT_TYPE = "http.message.content-type.";

	// Constructors ////////////////////////////////////////////////////////////

	private final Map<ResponseCode, Integer> httpCodes = new HashMap<>();
	private final Map<Integer, ResponseCode> coapCodes = new HashMap<>();
	private final Map<String, Object> httpMethods = new HashMap<>();
	private final Map<Code, String> coapMethods = new HashMap<>();

	public MappingProperties(String fileName) {
		init();
		initUserDefined(fileName);
		for (String key : stringPropertyNames()) {
			if (key.startsWith(KEY_COAP_CODE)) {
				initResponseCode(key);
			} else if (key.startsWith(KEY_HTTP_CODE)) {
				initHttpCode(key);
			} else if (key.startsWith(KEY_HTTP_METHOD)) {
				initHttpMethod(key);
			} else if (key.startsWith(KEY_COAP_METHOD)) {
				initCoapMethod(key);
			}
		}
	}

	private void initResponseCode(String key) {
		int httpCode = getInt(key);
		ResponseCode code = ResponseCode.valueOfText(key.substring(KEY_COAP_CODE.length()));
		if (code != null) {
			httpCodes.put(code, httpCode);
		}
	}

	private void initHttpCode(String key) {
		String tag = getStr(key);
		ResponseCode code = ResponseCode.valueOfText(tag);
		Integer httpCode = Integer.valueOf(key.substring(KEY_HTTP_CODE.length()), 10);
		if (httpCode != null && code != null) {
			coapCodes.put(httpCode, code);
		}
	}

	private void initHttpMethod(String key) {
		String mapKey = key.substring(KEY_HTTP_METHOD.length());
		String tag = getStr(key);
		Object code = Code.valueOfText(tag);
		if (code == null) {
			code = ResponseCode.valueOfText(tag);
		}
		if (code != null) {
			httpMethods.put(mapKey, code);
		}
	}

	private void initCoapMethod(String key) {
		String httpMethod = getStr(key);
		String tag = key.substring(KEY_COAP_METHOD.length());
		Code code = Code.valueOfText(tag);
		if (code != null && httpMethod != null) {
			coapMethods.put(code, httpMethod);
		}
	}

	public Code getCoapCode(String httpMethod) throws InvalidMethodException {
		Object code = httpMethods.get(httpMethod);
		if (code instanceof Code) {
			return (Code) code;
		} else if (code instanceof ResponseCode) {
			throw new InvalidMethodException((ResponseCode) code);
		}
		throw new InvalidMethodException(ResponseCode.BAD_GATEWAY);
	}

	public String getHttpMethod(Code code) {
		return coapMethods.get(code);
	}

	public Integer getHttpCode(ResponseCode code) {
		return httpCodes.get(code);
	}

	public ResponseCode getCoapResponseCode(Integer code) {
		return coapCodes.get(code);
	}

	public int getInt(String key) {
		String value = getProperty(key);
		if (value != null) {
			try {
				return Integer.parseInt(value.trim());
			} catch (NumberFormatException e) {
				LOG.error(String.format("Invalid integer property: %s=%s", key, value));
			}
		} else {
			LOG.error(String.format("Undefined integer property: %s", key));
		}
		return 0;
	}

	public String getStr(String key) {
		String value = getProperty(key);
		if (value == null) {
			LOG.error(String.format("Undefined string property: %s", key));
		}
		return value;
	}

	public boolean getBool(String key) {
		String value = getProperty(key);
		if (value != null) {
			try {
				return Boolean.parseBoolean(value);
			} catch (NumberFormatException e) {
				LOG.error(String.format("Invalid boolean property: %s=%s", key, value));
			}
		} else {
			LOG.error(String.format("Undefined boolean property: %s", key));
		}
		return false;
	}

	public void load(String fileName) throws IOException {
		InputStream in = new FileInputStream(fileName);
		load(in);
	}

	public void set(String key, int value) {
		setProperty(key, String.valueOf(value));
	}

	public void set(String key, String value) {
		setProperty(key, value);
	}

	public void set(String key, boolean value) {
		setProperty(key, String.valueOf(value));
	}

	public void store(String fileName) throws IOException {
		OutputStream out = new FileOutputStream(fileName);
		store(out, HEADER);
	}

	private void init() {

		/* HTTP Methods */
		set(KEY_HTTP_METHOD + "options", "5.01");
		set(KEY_HTTP_METHOD + "trace", "5.01");
		set(KEY_HTTP_METHOD + "connect", "5.01");
		set(KEY_HTTP_METHOD + "head", "0.01");
		set(KEY_HTTP_METHOD + "get", "0.01");
		set(KEY_HTTP_METHOD + "post", "0.02");
		set(KEY_HTTP_METHOD + "put", "0.03");
		set(KEY_HTTP_METHOD + "delete", "0.04");

		/* HTTP response codes */
		set(KEY_HTTP_CODE + "100", "5.02");
		set(KEY_HTTP_CODE + "101", "5.02");
		set(KEY_HTTP_CODE + "102", "5.02");

		set(KEY_HTTP_CODE + "200", "2.05");
		set(KEY_HTTP_CODE + "201", "2.01");
		set(KEY_HTTP_CODE + "202", "2.05");
		set(KEY_HTTP_CODE + "203", "2.05");
		set(KEY_HTTP_CODE + "20204", "2.04"); // 2.04 for POST 0.02 * 10000
		set(KEY_HTTP_CODE + "30204", "2.04"); // 2.04 for PUT  0.03 * 10000
		set(KEY_HTTP_CODE + "40204", "2.02"); // 2.02 for DELETE 0.04 * 10000
		set(KEY_HTTP_CODE + "205", "2.05");
		set(KEY_HTTP_CODE + "206", "2.05");
		set(KEY_HTTP_CODE + "207", "2.05");

		set(KEY_HTTP_CODE + "300", "5.02");
		set(KEY_HTTP_CODE + "301", "5.02");
		set(KEY_HTTP_CODE + "302", "5.02");
		set(KEY_HTTP_CODE + "303", "5.02");
		set(KEY_HTTP_CODE + "304", "2.03");
		set(KEY_HTTP_CODE + "305", "5.02");
		set(KEY_HTTP_CODE + "307", "5.02");

		set(KEY_HTTP_CODE + "400", "4.00");
		set(KEY_HTTP_CODE + "401", "4.01");
		set(KEY_HTTP_CODE + "402", "4.00");
		set(KEY_HTTP_CODE + "403", "4.03");
		set(KEY_HTTP_CODE + "404", "4.04");
		set(KEY_HTTP_CODE + "405", "4.05");
		set(KEY_HTTP_CODE + "406", "4.06");
		set(KEY_HTTP_CODE + "407", "4.00");
		set(KEY_HTTP_CODE + "408", "4.00");
		set(KEY_HTTP_CODE + "409", "4.00");
		set(KEY_HTTP_CODE + "410", "4.00");
		set(KEY_HTTP_CODE + "411", "4.00");
		set(KEY_HTTP_CODE + "412", "4.12");
		set(KEY_HTTP_CODE + "413", "4.13");
		set(KEY_HTTP_CODE + "414", "4.00");
		set(KEY_HTTP_CODE + "415", "4.15");
		set(KEY_HTTP_CODE + "416", "4.00");
		set(KEY_HTTP_CODE + "417", "4.00");
		set(KEY_HTTP_CODE + "418", "4.00");
		set(KEY_HTTP_CODE + "419", "4.00");
		set(KEY_HTTP_CODE + "420", "4.00");
		set(KEY_HTTP_CODE + "422", "4.00");
		set(KEY_HTTP_CODE + "423", "4.00");
		set(KEY_HTTP_CODE + "424", "4.00");

		set(KEY_HTTP_CODE + "500", "5.00");
		set(KEY_HTTP_CODE + "501", "5.01");
		set(KEY_HTTP_CODE + "502", "5.02");
		set(KEY_HTTP_CODE + "503", "5.03");
		set(KEY_HTTP_CODE + "504", "5.04");
		set(KEY_HTTP_CODE + "505", "5.02");
		set(KEY_HTTP_CODE + "507", "5.00");

		/* CoAP Request Codes / Methods */
		set(KEY_COAP_METHOD + "0.01", "GET");
		set(KEY_COAP_METHOD + "0.02", "POST");
		set(KEY_COAP_METHOD + "0.03", "PUT");
		set(KEY_COAP_METHOD + "0.04", "DELETE");

		/* CoAP Response Codes */
		set(KEY_COAP_CODE + "2.01", 201);
		set(KEY_COAP_CODE + "2.02", 204); // RFC 7252, 5.9.1.2
		set(KEY_COAP_CODE + "2.03", 304); // RFC 7252, 5.9.1.3
		set(KEY_COAP_CODE + "2.04", 204);
		set(KEY_COAP_CODE + "2.05", 200); // RFC 7252, 5.9.1.5
		set(KEY_COAP_CODE + "4.00", 400);
		set(KEY_COAP_CODE + "4.01", 401);
		set(KEY_COAP_CODE + "4.02", 400);
		set(KEY_COAP_CODE + "4.03", 403);
		set(KEY_COAP_CODE + "4.04", 404);
		set(KEY_COAP_CODE + "4.05", 405);
		set(KEY_COAP_CODE + "4.06", 406);
		set(KEY_COAP_CODE + "4.12", 412);
		set(KEY_COAP_CODE + "4.13", 413);
		set(KEY_COAP_CODE + "4.15", 415);
		set(KEY_COAP_CODE + "5.00", 500);
		set(KEY_COAP_CODE + "5.01", 501);
		set(KEY_COAP_CODE + "5.02", 502);
		set(KEY_COAP_CODE + "5.03", 503);
		set(KEY_COAP_CODE + "5.04", 504);
		set(KEY_COAP_CODE + "5.05", 502);

		/* HTTP header options */
		set("http.message.header.content-type", OptionNumberRegistry.CONTENT_FORMAT);
		set("http.message.header.accept", OptionNumberRegistry.ACCEPT);
		set("http.message.header.if-match", OptionNumberRegistry.IF_MATCH);
		set("http.message.header.if-none-match", OptionNumberRegistry.IF_NONE_MATCH);
		set("http.message.header.etag", OptionNumberRegistry.ETAG);
		set("http.message.header.cache-control", OptionNumberRegistry.MAX_AGE);

		/* CoAP header options */
		set("coap.message.option." + OptionNumberRegistry.CONTENT_FORMAT, "Content-Type");
		set("coap.message.option." + OptionNumberRegistry.MAX_AGE, "Cache-Control");
		set("coap.message.option." + OptionNumberRegistry.ETAG, "Etag");
		set("coap.message.option." + OptionNumberRegistry.LOCATION_PATH, "Location");
		set("coap.message.option." + OptionNumberRegistry.LOCATION_QUERY, "Location");
		set("coap.message.option." + OptionNumberRegistry.ACCEPT, "Accept");
		set("coap.message.option." + OptionNumberRegistry.IF_MATCH, "If-Match");
		set("coap.message.option." + OptionNumberRegistry.IF_NONE_MATCH, "If-None-Match");

		/* Media types */
		set("http.message.content-type.text/plain", MediaTypeRegistry.TEXT_PLAIN);
		set("http.message.content-type.application/link-format", MediaTypeRegistry.APPLICATION_LINK_FORMAT);
		set("http.message.content-type.application/xml", MediaTypeRegistry.APPLICATION_XML);
		set("http.message.content-type.application/json", MediaTypeRegistry.APPLICATION_JSON);

		set("coap.message.media." + MediaTypeRegistry.TEXT_PLAIN, "text/plain; charset=utf-8");
		set("coap.message.media." + MediaTypeRegistry.APPLICATION_LINK_FORMAT, "application/link-format");
		set("coap.message.media." + MediaTypeRegistry.APPLICATION_XML, "application/xml");
		set("coap.message.media." + MediaTypeRegistry.APPLICATION_JSON, "application/json; charset=UTF-8");

	}

	private void initUserDefined(String fileName) {
		try {
			load(fileName);
		} catch (IOException e) {
			// file does not exist:
			// write default properties
			try {
				store(fileName);
			} catch (IOException e1) {
				LOG.warn(String.format("Failed to create configuration file: %s", e1.getMessage()));
			}
		}
	}
}
