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
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.INTERNAL_SERVER_ERROR;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock.WriteLock;
import java.util.function.Consumer;

import org.eclipse.californium.cloud.BaseServer;
import org.eclipse.californium.cloud.option.ResponseCodeOption;
import org.eclipse.californium.cloud.option.ServerCustomOptions;
import org.eclipse.californium.cloud.option.TimeOption;
import org.eclipse.californium.cloud.resources.ProtectedCoapResource;
import org.eclipse.californium.cloud.s3.forward.HttpForwardConfiguration;
import org.eclipse.californium.cloud.s3.forward.HttpForwardConfigurationProvider;
import org.eclipse.californium.cloud.s3.forward.HttpForwardService;
import org.eclipse.californium.cloud.s3.forward.HttpForwardServiceManager;
import org.eclipse.californium.cloud.s3.option.S3ProxyCustomOptions;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClientProvider;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyRequest;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyRequest.Builder;
import org.eclipse.californium.cloud.s3.util.DomainApplicationAnonymous;
import org.eclipse.californium.cloud.s3.util.DomainPrincipalInfo;
import org.eclipse.californium.cloud.s3.util.MultiConsumer;
import org.eclipse.californium.cloud.util.PrincipalInfo;
import org.eclipse.californium.cloud.util.PrincipalInfo.Type;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.UriQueryParameter;
import org.eclipse.californium.core.coap.option.OpaqueOption;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.core.server.resources.ResourceAttributes;
import org.eclipse.californium.elements.auth.ApplicationAuthorizer;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.LeastRecentlyUpdatedCache;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Devices resource.
 * <p>
 * Keeps the content of POST request as sub-resource using the principal's name
 * and domain as path of the sub-resource. e.g.:
 * 
 * <code>
 * coaps://${host}/devices POST "Hi!" by principal "Client_identity"
 * </code>
 * 
 * <p>
 * results in a resource:
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
 * 
 * <p>
 * Supported query parameter:
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
 * <p>
 * Example:
 * 
 * <code>
 * coaps://${host}/devices?acl=public-read&amp;read&amp;write" POST "Temperature: 25.4°"
 *  by principal "dev-1200045", domain "weather"
 * </code>
 * 
 * <p>
 * results in a S3 resource:
 * 
 * <code>
 * s3://${weather-bucket}/devices/dev-1200045/2022-11-03/17:14:46.645" with content "Temperature: 25.4°".
 * </code>
 * 
 * <p>
 * (Default for "write" argument is "${date}/${time}".)
 * 
 * and returns the content of
 * 
 * <code>
 * s3://${weather-bucket}/devices/dev-1200045/config".
 * </code>
 * 
 * <p>
 * (Default for "read" argument is "config".)
 * 
 * @since 3.12
 */
public class S3Devices extends ProtectedCoapResource {

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
	 * URI query parameter to append some lines to a series-resource. Obsolete.
	 * Only used to not break communication of devices in field.
	 */
	public static final String URI_QUERY_OPTION_SERIES = "series";
	/**
	 * URI query parameter to forward request via http.
	 * 
	 * @since 3.13
	 */
	public static final String URI_QUERY_OPTION_FORWARD = "forward";
	/**
	 * Supported query parameter.
	 */
	private static final List<String> SUPPORTED = Arrays.asList(URI_QUERY_OPTION_READ, URI_QUERY_OPTION_WRITE,
			URI_QUERY_OPTION_SERIES, URI_QUERY_OPTION_ACL, URI_QUERY_OPTION_FORWARD);

	private final long minutes;

	private final int maxDevices;

	private final ConcurrentHashMap<String, Resource> domains;

	private final S3ProxyClientProvider s3Clients;

	private final HttpForwardConfigurationProvider httpForwardConfigurationProvider;

	private final int[] CONTENT_TYPES = { TEXT_PLAIN, APPLICATION_OCTET_STREAM, APPLICATION_JSON, APPLICATION_CBOR,
			APPLICATION_XML, APPLICATION_JAVASCRIPT, APPLICATION_LINK_FORMAT };

	/**
	 * Creates devices resource.
	 * 
	 * @param config configuration
	 * @param s3Clients s3 client to persist the requests.
	 * @param httpForwardConfigurationProvider http forward configuration
	 *            provider.
	 */
	public S3Devices(Configuration config, S3ProxyClientProvider s3Clients,
			HttpForwardConfigurationProvider httpForwardConfigurationProvider) {
		super(RESOURCE_NAME, Type.DEVICE, Type.ANONYMOUS_DEVICE, Type.APPL_AUTH_DEVICE);
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
		this.httpForwardConfigurationProvider = httpForwardConfigurationProvider;
	}

	@Override
	protected ResponseCode checkOperationPermission(PrincipalInfo info, Exchange exchange, boolean write) {
		if (info.type == Type.DEVICE || info.type == Type.APPL_AUTH_DEVICE) {
			return null;
		}
		if (info.type == Type.ANONYMOUS_DEVICE && exchange.getRequest().getCode() == Code.POST) {
			return null;
		}
		return FORBIDDEN;
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
			final String domain = DomainPrincipalInfo.getDomain(getPrincipal(exchange));
			List<String> query = exchange.getRequestOptions().getUriQueryStrings();
			if (query.size() > 1) {
				exchange.respond(BAD_OPTION, "only one search query is supported!", TEXT_PLAIN);
				return;
			}
			Set<WebLink> subTree = new ConcurrentSkipListSet<>();
			Resource resource = domains.get(domain);
			if (resource != null) {
				LinkFormat.addSubTree(resource, query, subTree);
			}
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

		final Principal principal = getPrincipal(exchange);
		final DomainPrincipalInfo info = DomainPrincipalInfo.getPrincipalInfo(principal);
		boolean forward = false;
		String read = null;
		String write = null;
		try {
			UriQueryParameter helper = exchange.getRequestOptions().getUriQueryParameter(SUPPORTED);
			LOGGER.info("URI-Query: {} {}", exchange.getRequestOptions().getUriQuery(), info);
			List<Option> others = exchange.getRequestOptions().getOthers();
			if (!others.isEmpty()) {
				LOGGER.info("Other options: {} {}", others, info);
			}
			forward = helper.hasParameter(URI_QUERY_OPTION_FORWARD);
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
			exchange.respond(response);
			return;
		}

		Request request = exchange.advanced().getRequest();
		final TimeOption timeOption = TimeOption.getMessageTime(request);
		final long time = timeOption.getLongValue();

		if (info.type == Type.ANONYMOUS_DEVICE ||
			info.type == Type.APPL_AUTH_DEVICE) {

			if (forward && read == null && write == null) {
				// forward support for anonymous clients.
				if (forward && httpForwardConfigurationProvider != null) {
					final HttpForwardConfiguration configuration = httpForwardConfigurationProvider
							.getConfiguration(info);
					if (configuration != null && configuration.isValid()) {
						String serviceName = configuration.getServiceName();
						HttpForwardService service = HttpForwardServiceManager.getService(serviceName);
						if (service != null) {
							service.forwardPOST(request, info, configuration, (response) -> {
								if (principal == null && response.isSuccess()) {
									ApplicationAuthorizer authorizer = exchange.advanced().getApplicationAuthorizer();
									if (authorizer != null) {
										LOGGER.info("HTTP-forward: {} anonymous client authorized!",
												StringUtil.toLog(request.getSourceContext().getPeerAddress()));
										authorizer.authorize(request.getSourceContext(),
												DomainApplicationAnonymous.APPL_AUTH_PRINCIPAL);
									}
								}
								exchange.respond(response);
							});
							return;
						}
					}
				}
			}
			Response response = new Response(ResponseCode.UNAUTHORIZED);
			exchange.respond(response);
			return;
		}
		Response response = new Response(CHANGED);
		final String timestamp = format(time, ChronoUnit.MILLIS);
		S3ProxyClient s3Client = s3Clients.getProxyClient(info.domain);
		String position = null;

		LOGGER.info("S3: {}, {}", info.domain, s3Client.getExternalEndpoint());
		String writeExpanded = replaceVars(write, timestamp);
		request.setProtectFromOffload();
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
				device.setPost(request, position, time, writeExpanded);
				if (device.getParent() == null) {
					device.setParent(deviceDomain);
					keptPosts.put(info.name, device);
				}
				LOGGER.info("Domain: {}, {} devices", info.domain, keptPosts.size());
			} finally {
				lock.unlock();
			}
		}

		MultiConsumer<Response> multi = new MultiConsumer<Response>() {

			@Override
			public void complete(Map<String, Response> results) {
				Response read = results.get("read");
				Response write = results.get("write");
				Response forward = results.get("forward");
				Response response = write != null ? write : read;
				if (forward != null) {
					if (response == null || (forward.isSuccess() && forward.getPayloadSize() > 0)) {
						exchange.respond(forward);
						return;
					}
					// forward response code in custom option
					response.getOptions()
							.addOtherOption(S3ProxyCustomOptions.FORWARD_RESPONSE.create(forward.getCode()));
				}
				if (write != null && read != null) {
					if (write.getCode() == CHANGED && read.getCode() == CONTENT) {
						// Add get response
						OptionSet options = write.getOptions();
						options.setContentFormat(read.getOptions().getContentFormat());
						for (OpaqueOption etag : read.getOptions().getETags()) {
							options.addOtherOption(ServerCustomOptions.READ_ETAG.create(etag.getValue()));
						}
						write.setPayload(read.getPayload());
					}
					// forward response code in custom option
					write.getOptions().addOtherOption(ServerCustomOptions.READ_RESPONSE.create(read.getCode()));
					exchange.respond(write);
				} else if (write != null) {
					exchange.respond(write);
				} else if (read != null) {
					exchange.respond(read);
				} else {
					response = new Response(INTERNAL_SERVER_ERROR);
					response.setPayload("no internal response!");
					exchange.respond(response);
				}
			}
		};

		if (forward && httpForwardConfigurationProvider != null) {
			final HttpForwardConfiguration configuration = httpForwardConfigurationProvider.getConfiguration(info);
			if (configuration != null && configuration.isValid()) {
				String serviceName = configuration.getServiceName();
				HttpForwardService service = HttpForwardServiceManager.getService(serviceName);
				if (service != null) {
					final Consumer<Response> consumer = multi.create("forward");
					service.forwardPOST(request, info, configuration, consumer);
				}
			}
		}

		if (read != null && !read.isEmpty()) {
			List<Option> readEtag = request.getOptions().getOthers(ServerCustomOptions.READ_ETAG);
			List<OpaqueOption> etags = new ArrayList<OpaqueOption>(readEtag.size());
			for (Option option : readEtag) {
				etags.add((OpaqueOption) option);
			}
			S3ProxyRequest s3ReadRequest = S3ProxyRequest.builder(request).pathPrincipalIndex(1).subPath(read)
					.etags(etags).build();
			s3Client.get(s3ReadRequest, multi.create("read"));
		}

		if (writeExpanded != null && !writeExpanded.isEmpty()) {
			final Consumer<Response> putResponseConsumer = multi.create("write");

			Builder builder = S3ProxyRequest.builder(request).pathPrincipalIndex(1).subPath(writeExpanded);
			if (write.equals(writeExpanded)) {
				builder.timestamp(time);
			}
			s3Client.put(builder.build(), (s3Response) -> {
				// respond with time?
				final TimeOption responseTimeOption = timeOption.adjust();
				if (responseTimeOption != null) {
					s3Response.getOptions().addOtherOption(responseTimeOption);
				}
				putResponseConsumer.accept(s3Response);
				if (s3Response.isSuccess()) {
					LOGGER.info("Device {} updated!{}", info, visible ? " (public)" : " (private)");
				} else {
					LOGGER.info("Device {} update failed!", info);
				}
			});
		}

		if (multi.created()) {
			return;
		}
		// respond with time?
		final TimeOption responseTimeOption = timeOption.adjust();
		if (responseTimeOption != null) {
			response.getOptions().addOtherOption(responseTimeOption);
		}
		exchange.respond(response);
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
	 * Resource representing devices.
	 */
	public static class Device extends ProtectedCoapResource {

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

		@Override
		protected ResponseCode checkOperationPermission(PrincipalInfo info, Exchange exchange, boolean write) {
			if (!isVisible() && !getName().equals(info.name)) {
				return FORBIDDEN;
			}
			return null;
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
	 * Replaces supported variables.
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
