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
package org.eclipse.californium.proxy2.http;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.hc.core5.http.HttpStatus;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.elements.config.PropertiesUtility;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.option.OptionDefinition;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.proxy2.InvalidMethodException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class maps different protocol constants for the Cf cross-proxy.
 */
public class MappingProperties extends Properties {

	private static final Logger LOGGER = LoggerFactory.getLogger(MappingProperties.class);

	/**
	 * auto-generated to eliminate warning
	 */
	private static final long serialVersionUID = 4126898261482584755L;

	/** The header for Californium property files. */
	private static final String HEADER = "Californium Cross-Proxy2 mapping properties file";

	protected static final String KEY_COAP_METHOD = "coap.request.code.";
	protected static final String KEY_COAP_CODE = "coap.response.code.";
	protected static final String KEY_COAP_OPTION = "coap.message.option.";
	protected static final String KEY_COAP_MEDIA = "coap.message.media.";
	protected static final String KEY_HTTP_CODE = "http.response.code.";
	protected static final String KEY_HTTP_METHOD = "http.request.method.";
	protected static final String KEY_HTTP_HEADER = "http.message.header.";
	protected static final String KEY_HTTP_CONTENT_TYPE = "http.message.content-type.";

	// Constructors ////////////////////////////////////////////////////////////

	protected final AtomicBoolean initialized = new AtomicBoolean();
	protected final Map<String, Object> httpMethods = new ConcurrentHashMap<>();
	protected final Map<Code, String> coapCodes = new ConcurrentHashMap<>();
	protected final Map<Integer, ResponseCode> httpStatusCodes = new ConcurrentHashMap<>();
	protected final Map<ResponseCode, Integer> coapResponseCodes = new ConcurrentHashMap<>();
	protected final Map<String, Integer> httpMediaTypes = new ConcurrentHashMap<>();
	protected final Map<Integer, String> coapMediaTypes = new ConcurrentHashMap<>();
	protected final Map<String, Integer> httpHeaders = new ConcurrentHashMap<>();
	protected final Map<Integer, String> coapOptions = new ConcurrentHashMap<>();

	/**
	 * Create default mapping properties.
	 * 
	 * @since 3.0
	 */
	public MappingProperties() {
		init();
		initMaps();
	}

	/**
	 * Create mapping properties from file.
	 * 
	 * @param fileName properties file name
	 */
	public MappingProperties(String fileName) {
		init();
		initUserDefined(fileName);
		initMaps();
	}

	/**
	 * Clear maps.
	 * 
	 * @since 3.0
	 */
	protected void clearMaps() {
		httpMethods.clear();
		coapCodes.clear();
		httpStatusCodes.clear();
		coapResponseCodes.clear();
		httpMediaTypes.clear();
		coapMediaTypes.clear();
		httpHeaders.clear();
		coapOptions.clear();
	}

	/**
	 * Initialize specific maps from raw properties.
	 * 
	 * @since 3.0
	 */
	protected void initMaps() {
		for (String key : stringPropertyNames()) {
			initMaps(key);
		}
		initialized.set(true);
	}

	/**
	 * Initialize specific maps from raw property.
	 * 
	 * @param key key for entry to load
	 * @since 3.0
	 */
	protected void initMaps(String key) {
		if (key.startsWith(KEY_COAP_CODE)) {
			initResponseCode(key);
		} else if (key.startsWith(KEY_HTTP_CODE)) {
			initHttpCode(key);
		} else if (key.startsWith(KEY_HTTP_METHOD)) {
			initHttpMethod(key);
		} else if (key.startsWith(KEY_COAP_METHOD)) {
			initCoapMethod(key);
		} else if (key.startsWith(KEY_COAP_MEDIA)) {
			initCoapMediaType(key);
		} else if (key.startsWith(KEY_HTTP_CONTENT_TYPE)) {
			initHttpMediaType(key);
		} else if (key.startsWith(KEY_COAP_OPTION)) {
			initCoapOption(key);
		} else if (key.startsWith(KEY_HTTP_HEADER)) {
			initHttpHeader(key);
		}
	}

	/**
	 * Initialize {@link #coapResponseCodes} from raw property.
	 * 
	 * @param key key for entry to load
	 */
	protected void initResponseCode(String key) {
		Integer httpCode = getInteger(key);
		ResponseCode code = ResponseCode.valueOfText(getTag(KEY_COAP_CODE, key));
		if (httpCode != null && code != null) {
			coapResponseCodes.put(code, httpCode);
		}
	}

	/**
	 * Initialize {@link #httpStatusCodes} from raw property.
	 * 
	 * @param key key for entry to load
	 */
	protected void initHttpCode(String key) {
		ResponseCode code = ResponseCode.valueOfText(getString(key));
		Integer httpCode = getIntegerTag(KEY_HTTP_CODE, key);
		if (httpCode != null && code != null) {
			httpStatusCodes.put(httpCode, code);
		}
	}

	/**
	 * Initialize {@link #httpMethods} from raw property.
	 * 
	 * Load either {@link Code}, or {@link ResponseCode}, if method is not
	 * supported.
	 * 
	 * @param key key for entry to load
	 */
	protected void initHttpMethod(String key) {
		String tag = getTag(KEY_HTTP_METHOD, key);
		String coapCode = getString(key);
		Object code = Code.valueOfText(coapCode);
		if (code == null) {
			// some methods are not supported and
			// therefore the error code is configured instead
			code = ResponseCode.valueOfText(coapCode);
		}
		if (code != null) {
			httpMethods.put(tag.toLowerCase(), code);
		}
	}

	/**
	 * Initialize {@link #coapCodes} from raw property.
	 * 
	 * @param key key for entry to load
	 */
	protected void initCoapMethod(String key) {
		String httpMethod = getString(key);
		String tag = getTag(KEY_COAP_METHOD, key);
		Code code = Code.valueOfText(tag);
		if (code != null && httpMethod != null) {
			coapCodes.put(code, httpMethod);
		}
	}

	/**
	 * Initialize {@link #coapMediaTypes} from raw property.
	 * 
	 * @param key key for entry to load
	 * @since 3.0
	 */
	protected void initCoapMediaType(String key) {
		String httpMediaType = getString(key);
		Integer coapMediaType = getIntegerTag(KEY_COAP_MEDIA, key);
		if (coapMediaType != null && httpMediaType != null) {
			coapMediaTypes.put(coapMediaType, httpMediaType);
		}
	}

	/**
	 * Initialize {@link #httpMediaTypes} from raw property.
	 * 
	 * @param key key for entry to load
	 * @since 3.0
	 */
	protected void initHttpMediaType(String key) {
		Integer coapMediaType = getInteger(key);
		if (coapMediaType != null) {
			httpMediaTypes.put(getTag(KEY_HTTP_CONTENT_TYPE, key).toLowerCase(), coapMediaType);
		}
	}

	/**
	 * Initialize {@link #coapOptions} from raw property.
	 * 
	 * @param key key for entry to load
	 * @since 3.0
	 */
	protected void initCoapOption(String key) {
		String httpHeader = getString(key);
		Integer coapOption = getIntegerTag(KEY_COAP_OPTION, key);
		if (coapOption != null && httpHeader != null) {
			coapOptions.put(coapOption, httpHeader);
		}
	}

	/**
	 * Initialize {@link #httpHeaders} from raw property.
	 * 
	 * @param key key for entry to load
	 * @since 3.0
	 */
	protected void initHttpHeader(String key) {
		Integer coapOption = getInteger(key);
		if (coapOption != null) {
			httpHeaders.put(getTag(KEY_HTTP_HEADER, key), coapOption);
		}
	}

	/**
	 * Get tag from key.
	 * 
	 * Remove the prefix from key and trim the result.
	 * 
	 * @param prefix prefix to check and remove
	 * @param key key
	 * @return tag
	 * @throws IllegalArgumentException if prefix doesn't match or the left tag
	 *             is empty.
	 * @since 3.0
	 */
	protected String getTag(String prefix, String key) {
		if (key.startsWith(prefix)) {
			String tag = key.substring(prefix.length()).trim();
			if (tag.isEmpty()) {
				throw new IllegalArgumentException("key '" + key + "' has only prefix '" + prefix + "'!");
			}
			return tag;
		} else {
			throw new IllegalArgumentException("key '" + key + "' has not prefix '" + prefix + "'!");
		}
	}

	/**
	 * Get integer tag from key by removing the prefix.
	 * 
	 * @param prefix prefix to check and remove
	 * @param key key
	 * @return integer tag
	 * @throws IllegalArgumentException if prefix doesn't match or the left tag
	 *             is empty.
	 * @throws NumberFormatException if tag is no valid integer number.
	 * @since 3.0
	 */
	protected Integer getIntegerTag(String prefix, String key) {
		return Integer.valueOf(getTag(prefix, key), 10);
	}

	/**
	 * Get CoAP code for http method.
	 * 
	 * In difference to some other getters, this getter doesn't return
	 * {@code null}, but throws a InvalidMethodException with a
	 * {@code ResponseCode} as error details.
	 * 
	 * @param httpMethod http method
	 * @return CoAP code
	 * @throws NullPointerException if http method is {@code null}.
	 * @throws InvalidMethodException if no CoAP code is available for http
	 *             method
	 */
	public Code getCoapCode(String httpMethod) throws InvalidMethodException {
		if (httpMethod == null) {
			throw new NullPointerException("http method must not be null!");
		}
		Object code = httpMethods.get(httpMethod.toLowerCase());
		if (code instanceof Code) {
			return (Code) code;
		} else if (code instanceof ResponseCode) {
			throw new InvalidMethodException((ResponseCode) code);
		}
		throw new InvalidMethodException(ResponseCode.INTERNAL_SERVER_ERROR);
	}

	/**
	 * Get http method for CoAP code.
	 * 
	 * @param code CoAP code
	 * @return http method, or {@code null}, if not available.
	 */
	public String getHttpMethod(Code code) {
		return coapCodes.get(code);
	}

	/**
	 * Get http status code for CoAP response code.
	 * 
	 * @param code CoAP response code
	 * @return http status code, or {@code null}, if not available.
	 */
	public Integer getHttpStatusCode(ResponseCode code) {
		return coapResponseCodes.get(code);
	}

	/**
	 * Get CoAP response code for http status code.
	 * 
	 * @param coapMethod coap method code
	 * @param httpStatusCode http status code
	 * @return CoAP response code, or {@code null}, if not available.
	 * @throws NullPointerException if coap method is {@code null}.
	 * @since 3.0 (added coapMethod to parameter)
	 */
	public ResponseCode getCoapResponseCode(Code coapMethod, int httpStatusCode) {
		if (coapMethod == null) {
			throw new NullPointerException("coap method must not be null!");
		}
		if (httpStatusCode == HttpStatus.SC_NO_CONTENT) {
			// special mapping for http 2.04 using the coap request code
			// RFC 7252 5.9.1.2 and 5.9.1.4
			httpStatusCode += 10000 * coapMethod.value;
		}
		return httpStatusCodes.get(httpStatusCode);
	}

	/**
	 * Get CoAP media type for http mime type.
	 * 
	 * @param mimeType http mime type
	 * @return CoAP media type, or {@code null}, if not available.
	 * @throws NullPointerException if mime-type is {@code null}.
	 * @since 3.0
	 */
	public Integer getCoapMediaType(String mimeType) {
		if (mimeType == null) {
			throw new NullPointerException("mime type must not be null!");
		}
		return httpMediaTypes.get(mimeType.toLowerCase());
	}

	/**
	 * Get http mime type for CoAP media type.
	 * 
	 * @param coapMediaType CoAP media type
	 * @return http mime type, or {@code null}, if not available.
	 * @since 3.0
	 */
	public String getHttpMimeType(Integer coapMediaType) {
		return coapMediaTypes.get(coapMediaType);
	}

	/**
	 * Get CoAP option number for http header name.
	 * 
	 * @param httpHeader http header name
	 * @return CoAP option number, or {@code null}, if not available.
	 * @since 3.0
	 */
	public Integer getCoapOption(String httpHeader) {
		return httpHeaders.get(httpHeader);
	}

	/**
	 * Get CoAP option definition for http header name.
	 * 
	 * @param httpHeader http header name
	 * @return CoAP option definition, or {@code null}, if not available.
	 * @since 3.8
	 */
	public OptionDefinition getCoapOptionDefinition(String httpHeader) {
		Integer number = getCoapOption(httpHeader);
		if (number != null) {
			return StandardOptionRegistry.getDefaultOptionRegistry().getDefinitionByNumber(number);
		}
		return null;
	}

	/**
	 * Get http header name for CoAP option number.
	 * 
	 * @param coapOption CoAP option number
	 * @return http header name, or {@code null}, if not available.
	 * @since 3.0
	 */
	public String getHttpHeader(Integer coapOption) {
		return coapOptions.get(coapOption);
	}

	/**
	 * Get integer for key.
	 * 
	 * @param key properties name
	 * @return integer, or {@code null}, if not available or value is not a
	 *         valid integer number
	 * @since 3.0
	 */
	protected Integer getInteger(String key) {
		String value = getString(key);
		if (value != null) {
			try {
				return Integer.valueOf(value);
			} catch (NumberFormatException e) {
				LOGGER.error(String.format("Invalid integer property: %s=%s", key, value));
			}
		}
		return null;
	}

	/**
	 * Get trimmed string for key.
	 * 
	 * @param key properties name
	 * @return trimmed string, or {@code null}, if not available or trimmed
	 *         string is empty
	 * @since 3.0
	 */
	protected String getString(String key) {
		String value = getProperty(key);
		if (value == null) {
			LOGGER.error("Undefined string property: {}", key);
			return null;
		}
		value = value.trim();
		if (value.isEmpty()) {
			LOGGER.error("Empty string property: {}", key);
			return null;
		}
		return value;
	}

	/**
	 * Load raw properties from file.
	 * 
	 * @param fileName properties filename
	 * @throws IOException if an i/o error occurs.
	 */
	protected void load(String fileName) throws IOException {
		InputStream in = new FileInputStream(fileName);
		try {
			load(in);
		} finally {
			in.close();
		}
		if (initialized.get()) {
			initMaps();
		}
	}

	/**
	 * Set raw integer property.
	 * 
	 * @param key key
	 * @param value value
	 */
	protected void set(String key, int value) {
		setProperty(key, String.valueOf(value));
		if (initialized.get()) {
			initMaps(key);
		}
	}

	/**
	 * Set raw text property.
	 * 
	 * @param key key
	 * @param value value
	 */
	protected void set(String key, String value) {
		setProperty(key, value);
		if (initialized.get()) {
			initMaps(key);
		}
	}

	/**
	 * Store raw properties in file.
	 * 
	 * @param fileName properties filename
	 * @throws IOException if an i/o error occurs.
	 */
	protected void store(String fileName) throws IOException {
		OutputStream out = new FileOutputStream(fileName);
		try {
			store(out, HEADER, fileName);
		} finally {
			out.close();
		}
	}

	/**
	 * Stores the configuration to a stream using a given header.
	 * 
	 * @param out stream to store
	 * @param header header to use
	 * @param resourceName resource name of store for logging.
	 * @throws NullPointerException if out stream or header is {@code null}
	 */
	public void store(OutputStream out, String header, String resourceName) {
		if (out == null) {
			throw new NullPointerException("output stream must not be null!");
		}
		if (header == null) {
			throw new NullPointerException("header must not be null!");
		}
		LOGGER.info("writing mapping properties to {}", resourceName);
		try {
			Set<String> keys = stringPropertyNames();
			List<String> sortedKeys = new ArrayList<>(keys);
			Collections.sort(sortedKeys);
			try (OutputStreamWriter fileWriter = new OutputStreamWriter(out)) {
				String line = PropertiesUtility.normalizeComments(header);
				fileWriter.write(line);
				fileWriter.write(StringUtil.lineSeparator());
				line = PropertiesUtility.normalizeComments(new Date().toString());
				fileWriter.write(line);
				fileWriter.write(StringUtil.lineSeparator());
				fileWriter.write("#");
				fileWriter.write(StringUtil.lineSeparator());
				for (String key : sortedKeys) {
					String value = getProperty(key);
					if (value == null) {
						throw new IllegalArgumentException("Definition for " + key + " not found!");
					}
					String encoded = PropertiesUtility.normalize(key, true);
					fileWriter.write(encoded);
					fileWriter.write('=');
					encoded = PropertiesUtility.normalize(value, false);
					fileWriter.write(encoded);
					fileWriter.write(StringUtil.lineSeparator());
				}
			}
		} catch (IOException e) {
			LOGGER.warn("cannot write mapping properties to {}: {}", resourceName, e.getMessage());
		}
	}

	/**
	 * Initialize user-defined values.
	 * 
	 * Load properties file, or create it, if missing.
	 * 
	 * @param fileName properties filename
	 */
	protected void initUserDefined(String fileName) {
		try {
			load(fileName);
		} catch (IOException e) {
			// file does not exist:
			// write default properties
			try {
				store(fileName);
			} catch (IOException e1) {
				LOGGER.warn(String.format("Failed to create configuration file: %s", e1.getMessage()));
			}
		}
	}

	/**
	 * Initialize raw properties with default values.
	 */
	protected void init() {

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
		set(KEY_HTTP_CODE + "30204", "2.04"); // 2.04 for PUT 0.03 * 10000
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
		set(KEY_COAP_CODE + "4.09", 409);
		set(KEY_COAP_CODE + "4.12", 412);
		set(KEY_COAP_CODE + "4.13", 413);
		set(KEY_COAP_CODE + "4.15", 415);
		set(KEY_COAP_CODE + "4.29", 429);
		set(KEY_COAP_CODE + "5.00", 500);
		set(KEY_COAP_CODE + "5.01", 501);
		set(KEY_COAP_CODE + "5.02", 502);
		set(KEY_COAP_CODE + "5.03", 503);
		set(KEY_COAP_CODE + "5.04", 504);
		set(KEY_COAP_CODE + "5.05", 502);

		/* HTTP header options */
		set(KEY_HTTP_HEADER + "content-type", OptionNumberRegistry.CONTENT_FORMAT);
		set(KEY_HTTP_HEADER + "content-location", OptionNumberRegistry.LOCATION_PATH);
		set(KEY_HTTP_HEADER + "accept", OptionNumberRegistry.ACCEPT);
		set(KEY_HTTP_HEADER + "if-match", OptionNumberRegistry.IF_MATCH);
		set(KEY_HTTP_HEADER + "if-none-match", OptionNumberRegistry.IF_NONE_MATCH);
		set(KEY_HTTP_HEADER + "etag", OptionNumberRegistry.ETAG);
		set(KEY_HTTP_HEADER + "cache-control", OptionNumberRegistry.MAX_AGE);

		/* CoAP header options */
		set(KEY_COAP_OPTION + OptionNumberRegistry.CONTENT_FORMAT, "Content-Type");
		set(KEY_COAP_OPTION + OptionNumberRegistry.MAX_AGE, "Cache-Control");
		set(KEY_COAP_OPTION + OptionNumberRegistry.ETAG, "Etag");
		set(KEY_COAP_OPTION + OptionNumberRegistry.LOCATION_PATH, "Content-Location");
		set(KEY_COAP_OPTION + OptionNumberRegistry.LOCATION_QUERY, "Content-Location");
		set(KEY_COAP_OPTION + OptionNumberRegistry.ACCEPT, "Accept");
		set(KEY_COAP_OPTION + OptionNumberRegistry.IF_MATCH, "If-Match");
		set(KEY_COAP_OPTION + OptionNumberRegistry.IF_NONE_MATCH, "If-None-Match");

		/* Media types */
		set(KEY_HTTP_CONTENT_TYPE + "text/plain", MediaTypeRegistry.TEXT_PLAIN);
		set(KEY_HTTP_CONTENT_TYPE + "text/html", MediaTypeRegistry.TEXT_PLAIN);
		set(KEY_HTTP_CONTENT_TYPE + "text/xml", MediaTypeRegistry.APPLICATION_XML);
		set(KEY_HTTP_CONTENT_TYPE + "text", MediaTypeRegistry.TEXT_PLAIN);
		set(KEY_HTTP_CONTENT_TYPE + "application/link-format", MediaTypeRegistry.APPLICATION_LINK_FORMAT);
		set(KEY_HTTP_CONTENT_TYPE + "application/xml", MediaTypeRegistry.APPLICATION_XML);
		set(KEY_HTTP_CONTENT_TYPE + "application/json", MediaTypeRegistry.APPLICATION_JSON);
		set(KEY_HTTP_CONTENT_TYPE + "application/cbor", MediaTypeRegistry.APPLICATION_CBOR);

		set(KEY_COAP_MEDIA + MediaTypeRegistry.TEXT_PLAIN, "text/plain; charset=UTF-8");
		set(KEY_COAP_MEDIA + MediaTypeRegistry.APPLICATION_LINK_FORMAT, "application/link-format");
		set(KEY_COAP_MEDIA + MediaTypeRegistry.APPLICATION_XML, "application/xml");
		set(KEY_COAP_MEDIA + MediaTypeRegistry.APPLICATION_JSON, "application/json; charset=UTF-8");

		if (initialized.get()) {
			initMaps();
		}
	}

}
