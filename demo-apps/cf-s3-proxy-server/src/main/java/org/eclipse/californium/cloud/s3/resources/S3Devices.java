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
package org.eclipse.californium.cloud.s3.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.BAD_OPTION;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.FORBIDDEN;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.UNAUTHORIZED;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_CBOR;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JAVASCRIPT;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_LINK_FORMAT;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_OCTET_STREAM;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_XML;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.security.Principal;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock.WriteLock;
import java.util.function.Consumer;

import org.eclipse.californium.cloud.BaseServer;
import org.eclipse.californium.cloud.option.ReadEtagOption;
import org.eclipse.californium.cloud.option.ReadResponseOption;
import org.eclipse.californium.cloud.option.TimeOption;
import org.eclipse.californium.cloud.s3.proxy.S3AsyncProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClientProvider;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyRequest;
import org.eclipse.californium.cloud.s3.util.DomainDeviceManager;
import org.eclipse.californium.cloud.s3.util.DomainDeviceManager.DomainDeviceInfo;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.UriQueryParameter;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.core.server.resources.ResourceAttributes;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.LeastRecentlyUpdatedCache;
import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Devices resource.
 * <p>
 * Keeps the content of POST request as sub-resource using the principal's name
 * and domain as path of the sub-resource. e.g.:
 * </p>
 * 
 * <code>
 * coaps://${host}/devices POST "Hi!" by principal "Client_identity"
 * </code>
 * 
 * <p>
 * results in a resource:
 * </p>
 * 
 * <code>
 * "/devices/${device-domain}/Client_identity" with content "Hi!".
 * </code>
 * 
 * A GET request must then use that path in order to read the content.
 * 
 * <code>
 * coaps://${host}/devices/${device-domain}/Client_identity GET result in "Hi!"
 * </code>
 * 
 * <p>
 * Supported content types:
 * </p>
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
 * and returns a list of web-links for the current devices with public access
 * (ACL).
 * </p>
 * 
 * <p>
 * Supported query parameter:
 * </p>
 * 
 * <dl>
 * <dt>{@value #URI_QUERY_OPTION_ACL}</dt>
 * <dd>ACL for S3 objects. Default: "private".</dd>
 * <dt>{@value #URI_QUERY_OPTION_READ}</dt>
 * <dd>Sub resource for piggybacked read. Default argument "config".</dd>
 * <dt>{@value #URI_QUERY_OPTION_WRITE}</dt>
 * <dd>Sub resource to save message. Default argument "${now}".</dd>
 * <dt>{@value #URI_QUERY_OPTION_SERIES}</dt>
 * <dd>Use sub resource "series" to keep track of parts of the message.</dd>
 * </dl>
 * 
 * Default argument only applies, if the parameter is provided, but without
 * argument.
 * 
 * <p>
 * Supported custom options:
 * </p>
 * 
 * <dl>
 * <dt>{@link TimeOption}, {@value TimeOption#COAP_OPTION_TIME}</dt>
 * <dd>Time synchronization.</dd>
 * <dt>{@link ReadResponseOption},
 * {@value ReadResponseOption#COAP_OPTION_READ_RESPONSE}</dt>
 * <dd>Response code of piggybacked read request. See query parameter
 * {@value #URI_QUERY_OPTION_READ}</dd>
 * <dt>{@link ReadEtagOption},
 * {@value ReadEtagOption#COAP_OPTION_READ_ETAG}</dt>
 * <dd>ETAG of piggybacked read request. See query parameter
 * {@value #URI_QUERY_OPTION_READ}</dd>
 * </dl>
 * 
 * Example:
 * 
 * <code>
 * coaps://${host}/devices?acl=public-read&amp;read&amp;write" POST "Temperature: 25.4°"
 *  by principal "dev-1200045", domain "weather"
 * </code>
 * 
 * <p>
 * results in a S3 resource:
 * </p>
 * 
 * <code>
 * s3://${weather-bucket}/devices/dev-1200045/2022-11-03/17:14:46.645" with content "Temperature: 25.4°".
 * </code>
 * 
 * <p>
 * (Default for "write" argument is "${date}/${time}".)
 * 
 * and returns the content of
 * </p>
 * 
 * <code>
 * s3://${weather-bucket}/devices/dev-1200045/config".
 * </code>
 * 
 * <p>
 * (Default for "read" argument is "config".)
 * </p>
 * 
 * @since 3.12
 */
public class S3Devices extends CoapResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(S3Devices.class);

	public static final int SERIES_MAX_SIZE = 32 * 1024;

	public static final String RESOURCE_NAME = "devices";
	public static final String SUB_RESOURCE_NAME = "series";

	public static final String DEFAULT_READ_SUB_RESOURCE_NAME = "config";
	public static final String DEFAULT_WRITE_SUB_RESOURCE_NAME = "${date}/${time}";

	public static final String ATTRIBUTE_TIME = "time";
	public static final String ATTRIBUTE_POSITION = "pos";
	public static final String ATTRIBUTE_S3_LINK = "s3";

	/**
	 * URI query parameter to specify the ACL for S3.
	 */
	public static final String URI_QUERY_OPTION_ACL = "acl";
	/**
	 * URI query parameter to specify a sub-resource to read.
	 */
	public static final String URI_QUERY_OPTION_READ = "read";
	/**
	 * URI query parameter to specify a sub-resource to write.
	 */
	public static final String URI_QUERY_OPTION_WRITE = "write";
	/**
	 * URI query parameter to append some lines to a series-resource.
	 */
	public static final String URI_QUERY_OPTION_SERIES = "series";
	/**
	 * Supported query parameter.
	 */
	private static final List<String> SUPPORTED = Arrays.asList(URI_QUERY_OPTION_READ, URI_QUERY_OPTION_WRITE,
			URI_QUERY_OPTION_SERIES, URI_QUERY_OPTION_ACL);

	private final long minutes;

	private final int maxDevices;

	private final ConcurrentHashMap<String, Resource> domains;

	private final S3ProxyClientProvider s3Clients;

	private final int[] CONTENT_TYPES = { TEXT_PLAIN, APPLICATION_OCTET_STREAM, APPLICATION_JSON, APPLICATION_CBOR,
			APPLICATION_XML, APPLICATION_JAVASCRIPT, APPLICATION_LINK_FORMAT };

	/**
	 * Create devices resource.
	 * 
	 * @param config configuration
	 * @param s3Clients s3 client to persist the requests.
	 */
	public S3Devices(Configuration config, S3ProxyClientProvider s3Clients) {
		super(RESOURCE_NAME);
		if (s3Clients == null) {
			throw new NullPointerException("s3client must not be null!");
		}
		Arrays.sort(CONTENT_TYPES);
		getAttributes().setTitle("Resource, which keeps track of POSTing devices.");
		getAttributes().addContentTypes(CONTENT_TYPES);
		minutes = config.get(BaseServer.CACHE_STALE_DEVICE_THRESHOLD, TimeUnit.MINUTES);
		maxDevices = config.get(BaseServer.CACHE_MAX_DEVICES);
		domains = new ConcurrentHashMap<>();
		this.s3Clients = s3Clients;
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
		return domains.get(name);
	}

	@Override // should be used for read-only
	public Collection<Resource> getChildren() {
		return domains.values();
	}

	@Override
	public void handleGET(final CoapExchange exchange) {
		Request request = exchange.advanced().getRequest();
		int accept = request.getOptions().getAccept();
		if (accept != UNDEFINED && accept != APPLICATION_LINK_FORMAT) {
			exchange.respond(NOT_ACCEPTABLE);
		} else {
			final Principal principal = request.getSourceContext().getPeerIdentity();
			final DomainDeviceInfo info = DomainDeviceManager.getDeviceInfo(principal);
			if (info == null) {
				exchange.respond(UNAUTHORIZED);
			} else {
				List<String> query = exchange.getRequestOptions().getUriQuery();
				if (query.size() > 1) {
					exchange.respond(BAD_OPTION, "only one search query is supported!", TEXT_PLAIN);
					return;
				}
				Set<WebLink> subTree = new ConcurrentSkipListSet<>();
				Resource resource = domains.get(info.domain);
				if (resource != null) {
					LinkFormat.addSubTree(resource, query, subTree);
				}
				Response response = new Response(CONTENT);
				response.setPayload(LinkFormat.serialize(subTree));
				response.getOptions().setContentFormat(APPLICATION_LINK_FORMAT);
				exchange.respond(response);
			}
		}
	}

	@Override
	public void handlePOST(final CoapExchange exchange) {
		handlePOST(exchange.advanced().getRequest(), new Consumer<Response>() {

			@Override
			public void accept(Response response) {
				exchange.respond(response);
			}
		});
	}

	public void handlePOST(Request request, final Consumer<Response> onResponse) {
		if (request == null) {
			throw new NullPointerException("request must not be null!");
		}
		if (onResponse == null) {
			throw new NullPointerException("onResponse must not be null!");
		}

		int format = request.getOptions().getContentFormat();
		if (format != UNDEFINED && Arrays.binarySearch(CONTENT_TYPES, format) < 0) {
			Response response = new Response(NOT_ACCEPTABLE);
			onResponse.accept(response);
			return;
		}

		boolean updateSeries = false;
		String read = null;
		String write = null;
		try {
			UriQueryParameter helper = request.getOptions().getUriQueryParameter(SUPPORTED);
			LOGGER.info("URI-Query: {}", request.getOptions().getUriQuery());
			List<Option> others = request.getOptions().getOthers();
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
			if (helper.hasParameter(URI_QUERY_OPTION_WRITE)) {
				write = helper.getArgument(URI_QUERY_OPTION_WRITE, DEFAULT_WRITE_SUB_RESOURCE_NAME);
				if (write.startsWith("/")) {
					throw new IllegalArgumentException("Absolute URI not supported for 'write'!");
				}
			}
		} catch (IllegalArgumentException ex) {
			Response response = new Response(BAD_OPTION);
			response.setPayload(ex.getMessage());
			onResponse.accept(response);
			return;
		}

		final TimeOption timeOption = TimeOption.getMessageTime(request);
		final long time = timeOption.getLongValue();

		Response response = new Response(CHANGED);
		final Principal principal = request.getSourceContext().getPeerIdentity();
		final DomainDeviceInfo info = DomainDeviceManager.getDeviceInfo(principal);
		LOGGER.info("S3: {}", info);
		if (info != null) {
			final String timestamp = format(time, ChronoUnit.MILLIS);
			final String domain = info.domain;
			S3ProxyClient s3Client = s3Clients.getProxyClient(domain);
			StringBuilder log = new StringBuilder();
			String position = null;

			LOGGER.info("S3: {}, {}", domain, s3Client.getExternalEndpoint());
			write = replaceVars(write, timestamp);
			if (format == TEXT_PLAIN && updateSeries) {
				String[] lines = request.getPayloadString().split("[\\n\\r]+");
				for (String line : lines) {
					if (line.startsWith("!")) {
						line = line.substring(1);
						log.append(line).append(',');
					}
				}
			}
			StringUtil.truncateTail(log, ",");
			request.setProtectFromOffload();
			Series series = null;
			String acl = S3ProxyRequest.getAcl(request, s3Client.getAcl());
			boolean visible = acl != null && acl.startsWith("public-");

			Resource deviceDomain = domains.get(info.domain);
			if (!(deviceDomain instanceof DeviceDomain)) {
				deviceDomain = new DeviceDomain(info.domain, minutes, maxDevices);
				Resource previous = domains.putIfAbsent(info.domain, deviceDomain);
				if (previous != null) {
					deviceDomain = previous;
				} else {
					deviceDomain.setParent(this);
				}
			}
			if (deviceDomain instanceof DeviceDomain) {
				LeastRecentlyUpdatedCache<String, Resource> keptPosts = ((DeviceDomain) deviceDomain).keptPosts;
				LOGGER.info("Domain: {}, {} devices", info.domain, keptPosts.size());
				WriteLock lock = keptPosts.writeLock();
				lock.lock();
				try {
					Device device;
					Resource child = keptPosts.update(info.name);
					if (child instanceof Device) {
						device = (Device) child;
					} else {
						device = new Device(info.name);
					}
					device.setVisible(visible);
					device.setPost(request, position, time, write);
					// workaround for javascript dependency on "series-" file
					series = device.appendSeries(log.toString(), timestamp);
					if (device.getParent() == null) {
						device.setParent(deviceDomain);
						keptPosts.put(info.name, device);
					}
				} finally {
					lock.unlock();
				}
			}

			final Consumer<Response> putResponseConsumer;
			if (read != null && !read.isEmpty()) {
				List<Option> readEtag = request.getOptions().getOthers(ReadEtagOption.DEFINITION);
				S3ProxyRequest s3ReadRequest = S3ProxyRequest.builder(request).pathPrincipalIndex(1).subPath(read)
						.etags(readEtag).build();
				MultiConsumer<Response> multi = new MultiConsumer<Response>() {

					@Override
					public void complete(Response t1, Response t2) {
						if (t2.getCode() == CHANGED && t1.getCode() == CONTENT) {
							// Add get response
							OptionSet options = t2.getOptions();
							options.setContentFormat(t1.getOptions().getContentFormat());
							for (byte[] etag : t1.getOptions().getETags()) {
								options.addOtherOption(ReadEtagOption.DEFINITION.create(etag));
							}
							t2.setPayload(t1.getPayload());
						}
						t2.getOptions().addOtherOption(new ReadResponseOption(t1.getCode()));
						onResponse.accept(t2);
					}
				};
				putResponseConsumer = multi.consumer2;
				s3Client.get(s3ReadRequest, multi.consumer1);
			} else {
				putResponseConsumer = onResponse;
			}
			S3ProxyRequest s3WriteRequest = S3ProxyRequest.builder(request).pathPrincipalIndex(1).subPath(write)
					.build();
			s3Client.put(s3WriteRequest, new Consumer<Response>() {

				@Override
				public void accept(Response response) {
					// respond with time?
					final TimeOption responseTimeOption = timeOption.adjust();
					if (responseTimeOption != null) {
						response.getOptions().addOtherOption(responseTimeOption);
					}
					putResponseConsumer.accept(response);
					if (response.isSuccess()) {
						LOGGER.info("Device {} updated!{}", info, visible ? " (public)" : " (private)");
					} else {
						LOGGER.info("Device {} update failed!", info);
					}
				}
			});

			if (series != null) {
				updateSeries(request, series, s3Client);
			}
			return;
		}
		// respond with time?
		final TimeOption responseTimeOption = timeOption.adjust();
		if (responseTimeOption != null) {
			response.getOptions().addOtherOption(responseTimeOption);
		}
		onResponse.accept(response);
	}

	private void updateSeries(Request request, Series series, S3ProxyClient s3Client) {
		String content;
		String subResouce;
		synchronized (series) {
			content = series.getContent();
			subResouce = series.getS3Link();
		}
		if (content != null) {
			S3ProxyRequest s3SeriesRequest = S3ProxyRequest.builder(request).pathPrincipalIndex(1).subPath(subResouce)
					.content(content.getBytes(StandardCharsets.UTF_8)).contentType("text/plain; charset=utf-8").build();
			s3Client.put(s3SeriesRequest, S3AsyncProxyClient.NOP);
		}
	}

	private static abstract class MultiConsumer<T> {

		private T t1;
		private T t2;

		public final Consumer<T> consumer1 = new Consumer<T>() {

			@Override
			public void accept(T t) {
				T o;
				synchronized (MultiConsumer.this) {
					t1 = t;
					o = t2;
				}
				if (t != null && o != null) {
					complete(t, o);
				}
			}

		};

		public final Consumer<T> consumer2 = new Consumer<T>() {

			@Override
			public void accept(T t) {
				T o;
				synchronized (MultiConsumer.this) {
					t2 = t;
					o = t1;
				}
				if (t != null && o != null) {
					complete(o, t);
				}
			}

		};

		abstract public void complete(T t1, T t2);
	}

	/**
	 * Resource representing a device domain
	 */
	public static class DeviceDomain extends CoapResource {

		private final LeastRecentlyUpdatedCache<String, Resource> keptPosts;

		private DeviceDomain(String name, long minutes, int maxDevices) {
			super(name, false);
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
	}

	/**
	 * Resource representing devices
	 */
	public static class Device extends CoapResource {

		private Series series = null;
		private volatile Request post;
		private volatile long time;

		private Device(String name) {
			super(name);
			setObservable(true);
		}

		private void setPost(Request post, String position, long time, String write) {
			synchronized (this) {
				long previousTime = this.time;

				this.post = post;
				this.time = time;

				ResourceAttributes attributes = new ResourceAttributes(getAttributes());
				attributes.clearContentType();
				if (post.getOptions().hasContentFormat()) {
					attributes.addContentType(post.getOptions().getContentFormat());
				}
				attributes.clearAttribute(ATTRIBUTE_S3_LINK);
				if (write != null) {
					attributes.addAttribute(ATTRIBUTE_S3_LINK, "/" + write);
				}
				String timestamp = format(time, ChronoUnit.SECONDS);
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

		private Series appendSeries(String values, String timestamp) {
			Series series = null;
			synchronized (this) {
				if (this.series != null) {
					if (!this.series.append(values, timestamp)) {
						delete(this.series);
						this.series = null;
					}
				}
				if (this.series == null) {
					this.series = new Series(timestamp);
					this.series.append(values, timestamp);
					add(this.series);
				}
				series = this.series;
				series.setVisible(isVisible());
			}
			return series;
		}

		private boolean hasPermission(Request request) {
			final Principal principal = request.getSourceContext().getPeerIdentity();
			final DomainDeviceInfo info = DomainDeviceManager.getDeviceInfo(principal);
			return info != null && (isVisible() || getName().equals(info.name));
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			Request devicePost = post;
			// get request to read out details
			Request request = exchange.advanced().getRequest();
			if (!hasPermission(request)) {
				exchange.respond(FORBIDDEN);
				return;
			}
			int format = devicePost.getOptions().getContentFormat();
			int accept = request.getOptions().getAccept();
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

	public static class Series extends CoapResource {

		private final String startDate;
		private final String s3Link;
		private final StringBuilder content = new StringBuilder();

		private Series(String timestamp) {
			super(SUB_RESOURCE_NAME);
			this.startDate = timestamp;
			this.s3Link = SUB_RESOURCE_NAME + "-" + timestamp;
			getAttributes().setAttribute(ATTRIBUTE_S3_LINK, "-" + timestamp);
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

		private Device getDevice() {
			return (Device) getParent();
		}

		private String getS3Link() {
			return s3Link;
		}

		private boolean append(String values, String timestamp) {
			synchronized (this) {
				int len = content.length();
				String line = timestamp + ": ";
				if (values != null && !values.isEmpty()) {
					line += values;
				}
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

		private String getContent() {
			return content.toString();
		}

		public void handleGET(CoapExchange exchange) {
			Request request = exchange.advanced().getRequest();
			if (!getDevice().hasPermission(request)) {
				exchange.respond(FORBIDDEN);
				return;
			}
			int accept = request.getOptions().getAccept();
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

	private static String format(long millis, ChronoUnit unit) {
		Instant instant = Instant.ofEpochMilli(millis).truncatedTo(unit);
		String time = DateTimeFormatter.ISO_INSTANT.format(instant);
		if (unit == ChronoUnit.MILLIS && instant.getNano() == 0) {
			// ISO_INSTANT doesn't use .000Z
			time = time.substring(0, time.length() - 1) + ".000Z";
		}
		return time;
	}

	/**
	 * Replace supported variables.
	 * 
	 * {@code ${now}}, {@code ${date}}, and {@code ${time}} are replaced with
	 * the current timestamp, either device time, if the device supports the
	 * {@link TimeOption}, or the server systemtime.
	 * 
	 * <pre>
	 * e.g.: 2022-11-05T17:03:41.615Z
	 * now := 2022-11-05T17:03:41.615Z
	 * date := 2022-11-05
	 * time := 17:03:41.615
	 * </pre>
	 * 
	 * @param value value with variables to replace
	 * @param timestamp timestamp
	 * @return value with replaced variables
	 */
	private String replaceVars(String value, String timestamp) {
		// 2022-11-05T17:03:41.615Z
		if (value != null && !value.isEmpty()) {
			value = value.replaceAll("(?<!\\$)\\$\\{now\\}", timestamp);
			value = value.replaceAll("(?<!\\$)\\$\\{date\\}", timestamp.substring(0, 10));
			value = value.replaceAll("(?<!\\$)\\$\\{time\\}", timestamp.substring(11, timestamp.length() - 1));
		}
		return value;
	}
}
