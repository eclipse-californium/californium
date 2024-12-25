/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.BAD_OPTION;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.FORBIDDEN;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_CBOR;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JAVASCRIPT;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_LINK_FORMAT;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_OCTET_STREAM;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_XML;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock.WriteLock;

import org.eclipse.californium.cloud.BaseServer;
import org.eclipse.californium.cloud.option.ResponseCodeOption;
import org.eclipse.californium.cloud.option.ServerCustomOptions;
import org.eclipse.californium.cloud.option.TimeOption;
import org.eclipse.californium.cloud.util.PrincipalInfo;
import org.eclipse.californium.cloud.util.PrincipalInfo.Type;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.UriQueryParameter;
import org.eclipse.californium.core.coap.option.OpaqueOption;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.core.server.resources.ResourceAttributes;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.LeastRecentlyUpdatedCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * Devices resource.
 * <p>
 * Keeps the content of POST request as sub-resource using the device name from
 * the additional info of the principal as name of the sub-resource. e.g.:
 * 
 * <code>
 * coaps://${host}/devices POST "Hi!" by principal "Client_identity"
 * </code>
 * 
 * <p>
 * results in a resource:
 * 
 * <code>
 * "/devices/Client_identity" with content "Hi!".
 * </code>
 * 
 * A GET request must then use that path in order to read the content.
 * 
 * <code>
 * coaps://${host}/devices/Client_identity GET result in "Hi!"
 * </code>
 * 
 * <p>
 * Supported content types:
 * 
 * <ul>
 * <li>{@link MediaTypeRegistry#TEXT_PLAIN}</li>
 * <li>{@link MediaTypeRegistry#APPLICATION_OCTET_STREAM}</li>
 * <li>{@link MediaTypeRegistry#APPLICATION_CBOR}</li>
 * <li>{@link MediaTypeRegistry#APPLICATION_JSON}</li>
 * <li>{@link MediaTypeRegistry#APPLICATION_XML}</li>
 * <li>{@link MediaTypeRegistry#APPLICATION_JAVASCRIPT}</li>
 * </ul>
 * 
 * <p>
 * For GET, {@link MediaTypeRegistry#APPLICATION_LINK_FORMAT} is also supported
 * and returns a list of web-links for the current devices.
 * <p>
 * Supported query parameter:
 * 
 * <dl>
 * <dt>{@value #URI_QUERY_OPTION_READ}</dt>
 * <dd>Sub resource for piggybacked read. Default argument "config".</dd>
 * <dt>{@value #URI_QUERY_OPTION_SERIES}</dt>
 * <dd>Use sub resource "series" to keep track of parts of the message.</dd>
 * </dl>
 * 
 * Default argument only applies, if the parameter is provided, but without
 * argument.
 * <p>
 * Supported custom options:
 * 
 * <dl>
 * <dt>{@link TimeOption}, {@value TimeOption#COAP_OPTION_TIME}</dt>
 * <dd>Time synchronization.</dd>
 * <dt>{@link ResponseCodeOption},
 * {@value ServerCustomOptions#COAP_OPTION_READ_RESPONSE}</dt>
 * <dd>Response code of piggybacked read request. See query parameter
 * {@value #URI_QUERY_OPTION_READ}</dd>
 * <dt>{@link OpaqueOption},
 * {@value ServerCustomOptions#COAP_OPTION_READ_ETAG}</dt>
 * <dd>ETAG of piggybacked read request. See query parameter
 * {@value #URI_QUERY_OPTION_READ}</dd>
 * </dl>
 * 
 * Example:
 * 
 * <code>
 * coaps://${host}/devices?read" POST "Temperature: 25.4°" by principal "dev-1200045"
 * </code>
 * 
 * <p>
 * results in a resource:
 * 
 * <code>
 * "/devices/dev-1200045" with content "Temperature: 25.4°".
 * </code>
 * 
 * <p>
 * and returns the content of
 * 
 * <code>
 * "/devices/dev-1200045/config".
 * </code>
 * 
 * <p>
 * (Default for "read" argument is "config".)
 * 
 * @since 3.12
 */
public class Devices extends ProtectedCoapResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(Devices.class);
	private static final Logger LOGGER_TRACKER = LoggerFactory.getLogger("org.eclipse.californium.gnss.tracker");

	private static final SimpleDateFormat ISO_DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

	public static final int SERIES_MAX_SIZE = 32 * 1024;

	public static final String RESOURCE_NAME = "devices";
	public static final String SUB_RESOURCE_NAME = "series";

	public static final String DEFAULT_READ_SUB_RESOURCE_NAME = "config";

	public static final String ATTRIBUTE_TIME = "time";
	public static final String ATTRIBUTE_POSITION = "pos";

	/**
	 * URI query parameter to specify a sub-resource to read.
	 */
	public static final String URI_QUERY_OPTION_READ = "read";
	/**
	 * URI query parameter to append some lines to a series-resource.
	 */
	public static final String URI_QUERY_OPTION_SERIES = "series";
	/**
	 * Supported query parameter.
	 */
	private static final List<String> SUPPORTED = Arrays.asList(URI_QUERY_OPTION_READ, URI_QUERY_OPTION_SERIES);

	private final LeastRecentlyUpdatedCache<String, Resource> keptPosts;

	private final int[] CONTENT_TYPES = { TEXT_PLAIN, APPLICATION_OCTET_STREAM, APPLICATION_JSON, APPLICATION_CBOR,
			APPLICATION_XML, APPLICATION_JAVASCRIPT, APPLICATION_LINK_FORMAT };

	/**
	 * Create device resource.
	 * 
	 * @param config configuration
	 */
	public Devices(Configuration config) {
		super(RESOURCE_NAME, Type.DEVICE, Type.WEB);
		Arrays.sort(CONTENT_TYPES);
		getAttributes().setTitle("Resource, which keeps track of POSTing devices.");
		getAttributes().addContentTypes(CONTENT_TYPES);
		long minutes = config.get(BaseServer.CACHE_STALE_DEVICE_THRESHOLD, TimeUnit.MINUTES);
		int maxDevices = config.get(BaseServer.CACHE_MAX_DEVICES);
		int minDevices = maxDevices / 10;
		if (minDevices < 100) {
			minDevices = maxDevices;
		}
		keptPosts = new LeastRecentlyUpdatedCache<>(minDevices, maxDevices, minutes, TimeUnit.MINUTES);
	}

	@Override
	public void add(Resource child) {
		throw new UnsupportedOperationException("Not supported!");
	}

	@Override
	public boolean delete(Resource child) {
		throw new UnsupportedOperationException("Not supported!");
	}

	@Override
	public Resource getChild(String name) {
		return keptPosts.get(name);
	}

	@Override // should be used for read-only
	public Collection<Resource> getChildren() {
		return keptPosts.values();
	}

	@Override
	public void handleGET(final CoapExchange exchange) {
		int accept = exchange.getRequestOptions().getAccept();
		if (accept != UNDEFINED && accept != APPLICATION_LINK_FORMAT) {
			exchange.respond(NOT_ACCEPTABLE);
		} else {
			List<String> query = exchange.getRequestOptions().getUriQueryStrings();
			if (query.size() > 1) {
				exchange.respond(BAD_OPTION, "only one search query is supported!", TEXT_PLAIN);
				return;
			}
			Set<WebLink> subTree = LinkFormat.getSubTree(this, query);
			Response response = new Response(CONTENT);
			response.setPayload(LinkFormat.serialize(subTree));
			response.getOptions().setContentFormat(APPLICATION_LINK_FORMAT);
			exchange.respond(response);
		}
	}

	@Override
	public void handlePOST(final CoapExchange exchange) {
		int format = exchange.getRequestOptions().getContentFormat();

		if (format != UNDEFINED && Arrays.binarySearch(CONTENT_TYPES, format) < 0) {
			exchange.respond(NOT_ACCEPTABLE);
			return;
		}

		boolean updateSeries = false;
		String read = null;
		try {
			UriQueryParameter helper = exchange.getRequestOptions().getUriQueryParameter(SUPPORTED);
			LOGGER.info("URI-Query: {}", exchange.getRequestOptions().getUriQuery());
			List<Option> others = exchange.getRequestOptions().getOthers();
			if (!others.isEmpty()) {
				LOGGER.info("Other options: {}", others);
			}
			updateSeries = helper.hasParameter(URI_QUERY_OPTION_SERIES);
			if (helper.hasParameter(URI_QUERY_OPTION_READ)) {
				read = helper.getArgument(URI_QUERY_OPTION_READ, DEFAULT_READ_SUB_RESOURCE_NAME);
				if (read.startsWith("/")) {
					throw new IllegalArgumentException("Absolute URI not supported for 'read'!");
				}
			}
		} catch (IllegalArgumentException ex) {
			Response response = new Response(BAD_OPTION);
			response.setPayload(ex.getMessage());
			exchange.respond(response);
			return;
		}

		PrincipalInfo info = getPrincipalInfo(exchange);
		Response response;
		String name = info.name;
		if (name != null) {
			Request request = exchange.advanced().getRequest();
			final TimeOption timeOption = TimeOption.getMessageTime(request);
			final long time = timeOption.getLongValue();
			String log = null;
			String position = null;
			String timestamp = format(time);

			response = new Response(CHANGED);
			if (format == TEXT_PLAIN) {
				String[] lines = request.getPayloadString().split("[\\n\\r]+");
				for (String line : lines) {
					if (line.startsWith("!")) {
						line = line.substring(1);
						if (log == null) {
							log = timestamp + ": " + line;
						} else {
							log += "," + line;
						}
					}
					if (line.startsWith("GNSS.") && line.length() > 7) {
						String tag = line.substring(0, 6);
						String value = line.substring(7);
						LOGGER_TRACKER.info("{}: {} {}", tag, name, value);
						position = value;
					} else if (line.startsWith("*GNSS.") && line.length() > 8) {
						String value = line.substring(8);
						position = "*" + value;
					}
				}
				if (log != null) {
					LOGGER_TRACKER.info("!LOG: {} {}", name, log);
					if (!updateSeries) {
						log = null;
					}
				}
			}
			request.setProtectFromOffload();
			WriteLock lock = keptPosts.writeLock();
			lock.lock();
			try {
				Device device;
				Resource child = keptPosts.update(name);
				if (child instanceof Device) {
					device = (Device) child;
				} else {
					device = new Device(name);
				}
				device.setPost(request, position, time);
				if (log != null) {
					device.appendSeries(log, timestamp);
				}
				if (device.getParent() == null) {
					device.setParent(this);
					keptPosts.put(name, device);
				}
			} finally {
				lock.unlock();
			}
			// respond with time?
			final TimeOption responseTimeOption = timeOption.adjust();
			if (responseTimeOption != null) {
				response.getOptions().addOtherOption(responseTimeOption);
			}
		} else {
			response = new Response(FORBIDDEN);
		}
		exchange.respond(response);
	}

	/**
	 * Resource representing devices.
	 */
	public static class Device extends ProtectedCoapResource {

		private Series series = null;
		private volatile Request post;
		private volatile long time;

		private Device(String name) {
			super(name, Type.DEVICE, Type.WEB);
			setObservable(true);
		}

		private void setPost(Request post, String position, long time) {
			synchronized (this) {
				long previousTime = this.time;

				this.post = post;
				this.time = time;

				ResourceAttributes attributes = new ResourceAttributes(getAttributes());
				attributes.clearContentType();
				if (post.getOptions().hasContentFormat()) {
					attributes.addContentType(post.getOptions().getContentFormat());
				}
				String timestamp = format(time);
				if (previousTime > 0 && time > 0) {
					long interval = TimeUnit.MILLISECONDS.toSeconds(time - previousTime);
					if (interval > 0) {
						long minutes = TimeUnit.SECONDS.toMinutes(interval + 5);
						if (minutes > 0) {
							timestamp += " (" + minutes + "min.)";
						} else {
							timestamp += " (" + interval + "sec.)";
						}
					}
				}
				attributes.setAttribute(ATTRIBUTE_TIME, timestamp);
				if (position != null && !position.isEmpty()) {
					attributes.setAttribute(ATTRIBUTE_POSITION, position);
				} else {
					attributes.clearAttribute(ATTRIBUTE_POSITION);
				}
				setAttributes(attributes);
			}
			changed();
		}

		private Series appendSeries(String line, String timestamp) {
			Series series = null;
			if (line != null && !line.isEmpty()) {
				synchronized (this) {
					if (this.series != null) {
						if (!this.series.append(line, timestamp)) {
							delete(this.series);
							this.series = null;
						}
					}
					if (this.series == null) {
						this.series = new Series(timestamp);
						this.series.append(line, timestamp);
						add(this.series);
					}
					series = this.series;
				}
			}
			return series;
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			Request devicePost = post;
			int format = devicePost.getOptions().getContentFormat();
			int accept = exchange.getRequestOptions().getAccept();
			if (accept == UNDEFINED) {
				accept = format == UNDEFINED ? APPLICATION_OCTET_STREAM : format;
			} else if (format == UNDEFINED) {
				if (accept != TEXT_PLAIN && accept != APPLICATION_OCTET_STREAM) {
					exchange.respond(NOT_ACCEPTABLE);
					return;
				}
			} else if (accept != format) {
				exchange.respond(NOT_ACCEPTABLE);
				return;
			}
			Response response = new Response(CONTENT);
			response.setPayload(devicePost.getPayload());
			response.getOptions().setContentFormat(accept);
			exchange.respond(response);
		}

		@Override
		public String toString() {
			return getName();
		}
	}

	public static class Series extends ProtectedCoapResource {

		private final String startDate;
		private final StringBuilder content = new StringBuilder();

		private Series(String timestamp) {
			super(SUB_RESOURCE_NAME, Type.WEB);
			this.startDate = timestamp;
		}

		@Override
		public void setParent(Resource parent) {
			super.setParent(parent);
			synchronized (this) {
				ResourceAttributes attributes = new ResourceAttributes(getAttributes());
				if (parent != null) {
					attributes.setTitle(parent.getName() + " => " + SUB_RESOURCE_NAME);
				} else {
					attributes.clearTitle();
				}
				setAttributes(attributes);
			}
		}

		private boolean append(String line, String timestamp) {
			synchronized (this) {
				int len = content.length();
				boolean swap = len + line.length() > SERIES_MAX_SIZE;
				if (swap || !startDate.regionMatches(0, timestamp, 0, 11)) {
					return false;
				}
				if (len > 0) {
					if (content.charAt(len - 1) != '\n') {
						content.append('\n');
					}
				}
				content.append(line);
				return true;
			}
		}

		public String getContent() {
			return content.toString();
		}

		public void handleGET(CoapExchange exchange) {
			int accept = exchange.getRequestOptions().getAccept();
			if (accept != UNDEFINED && accept != TEXT_PLAIN) {
				exchange.respond(NOT_ACCEPTABLE);
				return;
			}
			Response response = new Response(CONTENT);
			response.setPayload(content.toString());
			response.getOptions().setContentFormat(TEXT_PLAIN);
			exchange.respond(response);
		}

	}

	private static String format(long millis) {
		return ISO_DATE_FORMAT.format(new Date(millis));
	}
}
