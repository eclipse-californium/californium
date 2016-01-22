/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Francesco Corazza - HTTP cross-proxy
 ******************************************************************************/
package org.eclipse.californium.proxy;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.OptionNumberRegistry;


/**
 * This class maps different protocol constants for the Cf cross-proxy.
 */
public class MappingProperties extends java.util.Properties {

	private static final Logger LOG = Logger.getLogger(MappingProperties.class.getName());

	/**
	 * auto-generated to eliminate warning
	 */
	private static final long serialVersionUID = 4126898261482584755L;

	/** The header for Californium property files. */
	private static final String HEADER = "Californium Cross-Proxy mapping properties file";

	/** The name of the default properties file. */
	private static final String DEFAULT_FILENAME = "ProxyMapping.properties";

	// default properties used by the library
	public static final MappingProperties std = new MappingProperties(DEFAULT_FILENAME);
	
	// Constructors ////////////////////////////////////////////////////////////
	
	public MappingProperties(String fileName) {
		init();
		initUserDefined(fileName);
	}
	
	public Double getDbl(String key) {
		String value = getProperty(key);
		if (value != null) {
			try {
				return Double.parseDouble(value);
			} catch (NumberFormatException e) {
				LOG.severe(String.format("Invalid double property: %s=%s", key, value));
			}
		} else {
			LOG.severe(String.format("Undefined double property: %s", key));
		}
		return 0.0;
	}

	public int getInt(String key) {
		String value = getProperty(key);
		if (value != null) {
			try {
				return Integer.parseInt(value.trim());
			} catch (NumberFormatException e) {
				LOG.severe(String.format("Invalid integer property: %s=%s", key, value));
			}
		} else {
			LOG.severe(String.format("Undefined integer property: %s", key));
		}
		return 0;
	}

	public String getStr(String key) {
		String value = getProperty(key);
		if (value == null) {
			LOG.severe(String.format("Undefined string property: %s", key));
		}
		return value;
	}

	public boolean getBool(String key) {
		String value = getProperty(key);
		if (value != null) {
			try {
				return Boolean.parseBoolean(value);
			} catch (NumberFormatException e) {
				LOG.severe(String.format("Invalid boolean property: %s=%s", key, value));
			}
		} else {
			LOG.severe(String.format("Undefined boolean property: %s", key));
		}
		return false;
	}
	
	public void load(String fileName) throws IOException {
		InputStream in = new FileInputStream(fileName);
		load(in);
	}

	public void set(String key, double value) {
		setProperty(key, String.valueOf(value));
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
		set("http.request.method.options", "error.501");
		set("http.request.method.trace", "error.501");
		set("http.request.method.connect", "error.501");
		set("http.request.method.head", 1);
		set("http.request.method.get", 1);
		set("http.request.method.post", 2);
		set("http.request.method.put", 3);
		set("http.request.method.delete", 4);

		
		/* HTTP response codes */
		set("http.response.code.100", 162);
		set("http.response.code.101", 162);
		set("http.response.code.102", 162);
		
		set("http.response.code.200", 69);
		set("http.response.code.201", 65);
		set("http.response.code.202", 69);
		set("http.response.code.203", 69);
		set("http.response.code.205", 69);
		set("http.response.code.206", 69);
		set("http.response.code.207", 69);
		
		set("http.response.code.300", 162);
		set("http.response.code.301", 162);
		set("http.response.code.302", 162);
		set("http.response.code.303", 162);
		set("http.response.code.304", 67);
		set("http.response.code.305", 162);
		set("http.response.code.307", 162);
		
		set("http.response.code.400", 128);
		set("http.response.code.401", 129);
		set("http.response.code.402", 128);
		set("http.response.code.403", 131);
		set("http.response.code.404", 132);
		set("http.response.code.405", 133);
		set("http.response.code.406", 134);
		set("http.response.code.407", 128);
		set("http.response.code.408", 128);
		set("http.response.code.409", 128);
		set("http.response.code.410", 128);
		set("http.response.code.411", 128);
		set("http.response.code.412", 140);
		set("http.response.code.413", 141);
		set("http.response.code.414", 128);
		set("http.response.code.415", 143);
		set("http.response.code.416", 128);
		set("http.response.code.417", 128);
		set("http.response.code.418", 128);
		set("http.response.code.419", 128);
		set("http.response.code.420", 128);
		set("http.response.code.422", 128);
		set("http.response.code.423", 128);
		set("http.response.code.424", 128);
		
		set("http.response.code.500", 160);
		set("http.response.code.501", 161);
		set("http.response.code.502", 162);
		set("http.response.code.503", 163);
		set("http.response.code.504", 164);
		set("http.response.code.505", 162);
		set("http.response.code.507", 160);
		
		/* CoAP Response Codes */
		set("coap.response.code.65", 201);
		set("coap.response.code.66", 204);
		set("coap.response.code.67", 304);
		set("coap.response.code.68", 204);
		set("coap.response.code.69", 200);
		set("coap.response.code.128", 400);
		set("coap.response.code.129", 401);
		set("coap.response.code.130", 400);
		set("coap.response.code.131", 403);
		set("coap.response.code.132", 404);
		set("coap.response.code.133", 405);
		set("coap.response.code.134", 406);
		set("coap.response.code.140", 412);
		set("coap.response.code.141", 413);
		set("coap.response.code.143", 415);
		set("coap.response.code.160", 500);
		set("coap.response.code.161", 501);
		set("coap.response.code.162", 502);
		set("coap.response.code.163", 503);
		set("coap.response.code.164", 504);
		set("coap.response.code.165", 502);
		

		/* HTTP header options */
		set("http.message.header.content-type", OptionNumberRegistry.CONTENT_FORMAT);
		set("http.message.header.accept", OptionNumberRegistry.ACCEPT);
		set("http.message.header.if-match", OptionNumberRegistry.IF_MATCH);
		set("http.message.header.if-none-match", OptionNumberRegistry.IF_NONE_MATCH);
		set("http.message.header.etag", OptionNumberRegistry.ETAG);
		set("http.message.header.cache-control", OptionNumberRegistry.MAX_AGE);
		
		/* CoAP header options */
		set("coap.message.option."+OptionNumberRegistry.CONTENT_FORMAT, "Content-Type");
		set("coap.message.option."+OptionNumberRegistry.MAX_AGE, "Cache-Control");
		set("coap.message.option."+OptionNumberRegistry.ETAG, "Etag");
		set("coap.message.option."+OptionNumberRegistry.LOCATION_PATH, "Location");
		set("coap.message.option."+OptionNumberRegistry.LOCATION_QUERY, "Location");
		set("coap.message.option."+OptionNumberRegistry.ACCEPT, "Accept");
		set("coap.message.option."+OptionNumberRegistry.IF_MATCH, "If-Match");
		set("coap.message.option."+OptionNumberRegistry.IF_NONE_MATCH, "If-None-Match");
		
		
		/* Media types */
		set("http.message.content-type.text/plain", MediaTypeRegistry.TEXT_PLAIN);
		set("http.message.content-type.text/html", MediaTypeRegistry.TEXT_HTML);
		set("http.message.content-type.application/link-format", MediaTypeRegistry.APPLICATION_LINK_FORMAT);
		set("http.message.content-type.application/xml", MediaTypeRegistry.APPLICATION_XML);
		set("http.message.content-type.application/json", MediaTypeRegistry.APPLICATION_JSON);
		set("http.message.content-type.image/gif", MediaTypeRegistry.IMAGE_GIF);
		set("http.message.content-type.image/jpeg", MediaTypeRegistry.IMAGE_JPEG);
		set("http.message.content-type.image/png", MediaTypeRegistry.IMAGE_PNG);
		set("http.message.content-type.image/tiff", MediaTypeRegistry.IMAGE_TIFF);
		
		set("coap.message.media."+MediaTypeRegistry.TEXT_PLAIN, "text/plain; charset=utf-8");
		set("coap.message.media."+MediaTypeRegistry.TEXT_HTML, "text/html");
		set("coap.message.media."+MediaTypeRegistry.APPLICATION_LINK_FORMAT, "application/link-format");
		set("coap.message.media."+MediaTypeRegistry.APPLICATION_XML, "application/xml");
		set("coap.message.media."+MediaTypeRegistry.APPLICATION_JSON, "application/json; charset=UTF-8");
		set("coap.message.media."+MediaTypeRegistry.IMAGE_GIF, "image/gif");
		set("coap.message.media."+MediaTypeRegistry.IMAGE_JPEG, "image/jpeg");
		set("coap.message.media."+MediaTypeRegistry.IMAGE_PNG, "image/png");
		set("coap.message.media."+MediaTypeRegistry.IMAGE_TIFF, "image/tiff");
		
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
				LOG.warning(String.format("Failed to create configuration file: %s", e1.getMessage()));
			}
		}
	}
}
