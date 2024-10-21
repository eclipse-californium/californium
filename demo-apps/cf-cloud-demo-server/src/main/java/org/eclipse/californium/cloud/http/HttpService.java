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
package org.eclipse.californium.cloud.http;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.eclipse.californium.cloud.resources.Devices;
import org.eclipse.californium.cloud.util.CredentialsStore;
import org.eclipse.californium.cloud.util.PrincipalInfo;
import org.eclipse.californium.cloud.util.PrincipalInfoProvider;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.auth.AbstractExtensiblePrincipal;
import org.eclipse.californium.elements.auth.AdditionalInfo;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.SystemResourceMonitors.SystemResourceMonitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

/**
 * Https service.
 * <p>
 * Provides either forwarding to external site, a single page application in
 * javascript, or a simple http access to data sent via coap.
 * <p>
 * The simple http access is implemented with a simplified http2coap proxy. It
 * supports only very limited conversion from http to coap. Allows only GET
 * access to resource "diagnose" and "devices" with sub-resources.
 * <p>
 * For forwarding and data access no authentication is supported!
 * 
 * @since 3.12
 */
@SuppressWarnings("restriction")
public class HttpService {

	/**
	 * Logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(HttpService.class);

	/**
	 * Logger for fail2ban support.
	 */
	private final static Logger LOGGER_BAN = LoggerFactory.getLogger("org.eclipse.californium.ban");

	/**
	 * TLS any protocol version.
	 */
	private static final String TLS = "TLS";
	/**
	 * TLS 1.2 protocol version.
	 */
	private static final String TLS_1_2 = "TLSv1.2";
	/**
	 * TLS 1.3 protocol version.
	 */
	private static final String TLS_1_3 = "TLSv1.3";
	private static final String[] TLS_PROTOCOLS = { TLS_1_3, TLS_1_2 };
	private static final String[] TLS_PROTOCOLS_1_2_ONLY = { TLS_1_2 };
	/**
	 * Name of private key file.
	 */
	private static final String HTTPS_PRIVATE_KEY = "privkey.pem";
	/**
	 * Name of full chain file.
	 */
	private static final String HTTPS_FULL_CHAIN = "fullchain.pem";
	/**
	 * Name of {@link javax.xml.ws.spi.http.HttpExchange} attribute for
	 * application {@link Principal}.
	 * 
	 * @since 3.13
	 */
	public static final String ATTRIBUTE_PRINCIPAL = "principal";
	/**
	 * Service instance.
	 */
	private static volatile HttpService httpService;
	/**
	 * Local secure address.
	 */
	private final InetSocketAddress localSecureAddress;
	/**
	 * Supported TLS protocols.
	 */
	private final String[] protocols;
	/**
	 * Algorithm for SSLContext.
	 */
	private final String sslContextAlgorithm;
	/**
	 * SSL credentials for https.
	 */
	private final CredentialsStore credentialsStore;
	/**
	 * SSL context for https.
	 */
	private SSLContext context;
	/**
	 * Current node certificate.
	 */
	private X509Certificate node;
	/**
	 * Executor for http server.
	 */
	private volatile ExecutorService executor;
	/**
	 * Https server.
	 */
	private HttpsServer secureServer;
	private volatile boolean started;
	/**
	 * Handler map.
	 */
	private final Map<String, HttpHandler> handlers = new ConcurrentHashMap<>();

	/**
	 * Creates service.
	 * 
	 * @param localSecureAddress local address for secure endpoint (https).
	 * @param credentialsStore credentials
	 * @param sslContextAlgorithm algorithm for SSL context.
	 * @param protocols list of TLS protocols
	 */
	public HttpService(InetSocketAddress localSecureAddress, CredentialsStore credentialsStore,
			String sslContextAlgorithm, String[] protocols) {
		this.localSecureAddress = localSecureAddress;
		this.sslContextAlgorithm = sslContextAlgorithm;
		this.protocols = protocols == null ? null : protocols.clone();
		this.credentialsStore = credentialsStore;
		applyCredentials(credentialsStore.getCredentials());
		this.credentialsStore.setObserver((newCredentials) -> {
			if (newCredentials != null) {
				applyCredentials(newCredentials);
			}
		});
	}

	public Executor getExecutor() {
		return new Executor() {

			@Override
			public void execute(Runnable command) {
				Executor serverExecutor = HttpService.this.executor;
				if (serverExecutor == null) {
					throw new RejectedExecutionException("Target executor missing!");
				}
				serverExecutor.execute(command);
			}
		};
	}

	/**
	 * Sets HTTPS configuration from {@link SSLContext}.
	 * 
	 * @param sslContext context for HTTPS configuration
	 */
	public void setHttpsConfigurator(SSLContext sslContext) {
		if (secureServer != null && sslContext != null) {
			secureServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {

				@Override
				public void configure(HttpsParameters parameters) {
					parameters.setWantClientAuth(false);
					if (protocols != null) {
						try {
							boolean useTlsProtocols = false;
							String[] clientProtocols = parameters.getProtocols();
							if (clientProtocols == null || clientProtocols.length == 0) {
								LOGGER.trace("TLS: protocol info not available!");
								useTlsProtocols = true;
							} else {
								for (String protocol : clientProtocols) {
									LOGGER.trace("TLS: {}", protocol);
									if (protocol.equals(TLS_1_2)) {
										useTlsProtocols = true;
									}
								}
							}
							if (useTlsProtocols) {
								parameters.setProtocols(protocols);
								for (String protocol : protocols) {
									LOGGER.trace("TLS: set {}", protocol);
								}
							}
						} catch (Throwable t) {
							LOGGER.error("TLS:", t);
						}
					}
				}

			});
		} else {
			if (secureServer == null) {
				LOGGER.warn("missing https server!");
			}
			if (sslContext == null) {
				LOGGER.warn("missing TLS context!");
			}
		}
	}

	/**
	 * Creates context on {@link #secureServer}.
	 * 
	 * @param name path prefix of context
	 * @param handler handler for context
	 */
	public void createContext(String name, HttpHandler handler) {
		String url = name;
		if (!url.startsWith("/")) {
			url = "/" + url;
		}
		handlers.put(url, handler);
		if (secureServer != null) {
			secureServer.createContext(url, handler);
		}
	}

	/**
	 * Creates file handler.
	 * 
	 * @param resource path
	 * @param contentType content-type of response
	 * @param reload {@code true} to reload on access, {@code true} to cache.
	 * @see FileHandler
	 */
	public void createFileHandler(String resource, String contentType, boolean reload) {
		if (!resource.startsWith("http")) {
			// download resource from local server
			createContext(resource, new FileHandler(resource, contentType, reload));
		}
	}

	/**
	 * Starts https service.
	 */
	public void start() {
		executor = Executors.newCachedThreadPool();
		if (localSecureAddress != null && context != null) {
			try {
				secureServer = HttpsServer.create(localSecureAddress, 10);
				setHttpsConfigurator(context);
				secureServer.createContext("/favicon.ico", new FileHandler("image/x-icon"));
				for (Map.Entry<String, HttpHandler> context : handlers.entrySet()) {
					secureServer.createContext(context.getKey(), context.getValue());
				}
				// Thread control is given to executor service.
				secureServer.setExecutor(executor);
				secureServer.start();
				started = true;
				LOGGER.info("starting {} succeeded!", localSecureAddress);
			} catch (IOException ex) {
				LOGGER.warn("starting {} failed!", localSecureAddress, ex);
			}
		} else {
			if (localSecureAddress == null) {
				LOGGER.warn("missing local address!");
			}
			if (context == null) {
				LOGGER.warn("missing TLS context!");
			}
		}
	}

	/**
	 * Stops https service.
	 */
	public void stop() {
		started = false;
		if (secureServer != null) {
			// stop with 2s delay
			secureServer.stop(2);
			secureServer = null;
		}
		try {
			Thread.sleep(2000);
		} catch (InterruptedException e) {
		}
		if (executor != null) {
			executor.shutdown();
			executor = null;
		}
	}

	/**
	 * Applies new credentials for https-server.
	 * 
	 * @param newCredentials new credentials.
	 */
	private void applyCredentials(Credentials newCredentials) {
		X509Certificate[] certificateChain = newCredentials.getCertificateChain();
		if (certificateChain != null && certificateChain.length > 0) {
			if (node == null || !node.equals(certificateChain[0])) {
				PrivateKey privateKey = newCredentials.getPrivateKey();
				if (privateKey != null) {
					try {
						KeyManager[] keyManager = SslContextUtil.createKeyManager("server", privateKey,
								certificateChain);
						TrustManager[] trustManager = SslContextUtil.createTrustAllManager();
						SSLContext sslContext = SSLContext.getInstance(sslContextAlgorithm);
						sslContext.init(keyManager, trustManager, null);
						context = sslContext;
						node = certificateChain[0];
						if (started) {
							LOGGER.info("restart - certificates reloaded.");
							stop();
							start();
						}
					} catch (GeneralSecurityException ex) {
						LOGGER.warn("creating SSLcontext failed", ex);
					}
				} else {
					LOGGER.debug("private key missing.");
				}
			} else {
				LOGGER.debug("certificates not changed.");
			}
		} else {
			LOGGER.warn("missing certificates.");
		}
	}

	/**
	 * Creates resource monitor for automatic credentials reloading.
	 * 
	 * @return created resource monitor
	 */
	public SystemResourceMonitor getFileMonitor() {
		return credentialsStore.getMonitor();
	}

	/**
	 * Log headers in debug level.
	 * 
	 * @param title start tag for logging
	 * @param headers header to log.
	 */
	public static void logHeaders(String title, Headers headers) {
		if (LOGGER.isDebugEnabled()) {
			for (String key : headers.keySet()) {
				LOGGER.debug("{}: {} {}", title, key, headers.getFirst(key));
			}
		}
	}

	/**
	 * Respond http-request.
	 * 
	 * @param httpExchange http-exchange with request
	 * @param httpCode http-response code
	 * @param contentType response content type. May be {@code null}.
	 * @param payload response payload. May be {@code null}.
	 * @throws IOException if an i/o-error occurred
	 */
	public static void respond(HttpExchange httpExchange, int httpCode, String contentType, byte[] payload)
			throws IOException {
		try {
			if (payload == null) {
				switch (httpCode) {
				case 401:
					payload = "<h1>401 - Unauthorized!</h1>".getBytes(StandardCharsets.UTF_8);
					break;
				case 403:
					payload = "<h1>403 - Forbidden!</h1>".getBytes(StandardCharsets.UTF_8);
					break;
				case 404:
					payload = "<h1>404 - Not found!</h1>".getBytes(StandardCharsets.UTF_8);
					break;
				case 405:
					payload = "<h1>405 - Method not allowed!</h1>".getBytes(StandardCharsets.UTF_8);
					break;
				case 413:
					payload = "<h1>413 - Payload too large!</h1>".getBytes(StandardCharsets.UTF_8);
					break;
				case 500:
					payload = "<h1>500 - Internal Server Error</h1>".getBytes(StandardCharsets.UTF_8);
					break;
				default:
					break;
				}
				if (payload != null) {
					contentType = "text/html; charset=utf-8";
				}
			}
			long length = payload != null && payload.length > 0 ? payload.length : -1;
			if (contentType != null) {
				httpExchange.getResponseHeaders().set("Content-Type", contentType);
			}
			if (httpExchange.getRequestMethod().equals("HEAD")) {
				httpExchange.getResponseHeaders().set("content-length", Long.toString(length));
				httpExchange.getResponseHeaders().set("connection", "close");
				length = -1;
			}
			httpExchange.sendResponseHeaders(httpCode, length);
			logHeaders("response", httpExchange.getResponseHeaders());
			if (length > 0) {
				try (OutputStream out = httpExchange.getResponseBody()) {
					out.write(payload);
				}
				LOGGER.info("respond {} {} {} bytes", httpExchange.getRequestMethod(), httpCode, length);
			} else {
				LOGGER.info("respond {} {}", httpExchange.getRequestMethod(), httpCode);
			}
		} catch (IOException e) {
			LOGGER.warn("writing response to {} failed!", httpExchange.getRemoteAddress(), e);
		} catch (Throwable e) {
			LOGGER.warn("respond to {} failed!", httpExchange.getRemoteAddress(), e);
		}
	}

	/**
	 * Writes message to {@link #LOGGER_BAN}.
	 * <p>
	 * Intended to be used by {@code fail2ban}.
	 * 
	 * @param httpExchange http exchange to ban host
	 * @param topic topic of ban
	 */
	public static void ban(HttpExchange httpExchange, String topic) {
		if (LOGGER_BAN.isInfoEnabled()) {
			String address = httpExchange.getRemoteAddress().getAddress().getHostAddress();
			String protocol = httpExchange.getProtocol();
			String method = httpExchange.getRequestMethod();
			String uri = httpExchange.getRequestURI().toString();
			LOGGER_BAN.info("https: {} {} {} {} Ban: {}", method, uri, protocol, topic, address);
		}
	}

	/**
	 * Checks, if the requested URI is equivalent to the context path.
	 * 
	 * @param httpExchange http exchange
	 * @return {@code true} if both matches
	 */
	public static boolean strictPathCheck(HttpExchange httpExchange) {
		URI uri = httpExchange.getRequestURI();
		String path = httpExchange.getHttpContext().getPath();
		return path.equals(uri.getPath());
	}

	private static final PrincipalInfoProvider webAnonymousInfoProvider = new PrincipalInfoProvider() {

		@Override
		public PrincipalInfo getPrincipalInfo(Principal principal) {
			if (principal instanceof WebAnonymous) {
				return new PrincipalInfo("web", principal.getName(), PrincipalInfo.Type.WEB);
			}
			return null;
		}
	};

	public static class WebAnonymous extends AbstractExtensiblePrincipal<WebAnonymous> {

		private static final String NAME = "anonymous";

		protected WebAnonymous(AdditionalInfo additionalInfo) {
			super(additionalInfo);
		}

		@Override
		public String toString() {
			return NAME;
		}

		@Override
		public String getName() {
			return NAME;
		}

		@Override
		public WebAnonymous amend(AdditionalInfo additionalInfo) {
			return new WebAnonymous(additionalInfo);
		}

		public static WebAnonymous create() {
			Map<String, Object> info = new HashMap<>();
			info.put(PrincipalInfo.INFO_NAME, NAME);
			info.put(PrincipalInfo.INFO_PROVIDER, webAnonymousInfoProvider);
			return new WebAnonymous(AdditionalInfo.from(info));
		}
	}

	/**
	 * HTTP handler to forward request.
	 */
	public static class ForwardHandler implements HttpHandler {

		/**
		 * External meta-element, intended for automatic forwarding.
		 */
		private final String forwardLink;
		/**
		 * External section, intended for manual forwarding.
		 */
		private final String forwardTitle;

		/**
		 * Creates forward handler.
		 * 
		 * @param link link to forward to.
		 * @param title title of link.
		 */
		public ForwardHandler(String link, String title) {
			this.forwardLink = link;
			this.forwardTitle = title;
		}

		/**
		 * {@inheritDoc}
		 * 
		 * Respond to request with forwarding page.
		 */
		@Override
		public void handle(final HttpExchange httpExchange) throws IOException {
			final URI uri = httpExchange.getRequestURI();
			LOGGER.info("/request: {} {}", httpExchange.getRequestMethod(), uri);
			String method = httpExchange.getRequestMethod();
			String contentType = "text/html; charset=utf-8";
			byte[] payload = null;
			int httpCode = 405;
			if (method.equals("GET")) {
				String page = HtmlGenerator.createForwardPage(forwardLink, forwardTitle);
				httpCode = 200;
				payload = page.toString().getBytes(StandardCharsets.UTF_8);
			} else if (method.equals("HEAD")) {
				String page = HtmlGenerator.createForwardPage(forwardLink, forwardTitle);
				httpCode = 200;
				payload = page.toString().getBytes(StandardCharsets.UTF_8);
			}
			respond(httpExchange, httpCode, contentType, payload);
		}
	}

	/**
	 * HTTP handler for files, e.g. favicon.ico or java-script.
	 */
	public static class FileHandler implements HttpHandler {

		private final String path;
		private final String contentType;
		private final boolean classpath;
		private final boolean reload;
		private byte[] data;

		public FileHandler(String contentType) {
			if (contentType == null) {
				throw new NullPointerException("content-type must not be null!");
			}
			this.contentType = contentType;
			this.classpath = false;
			this.path = "";
			this.reload = false;
			load();
		}

		public FileHandler(String file, String contentType, boolean reload) {
			if (file == null) {
				throw new NullPointerException("file must not be null!");
			}
			if (contentType == null) {
				throw new NullPointerException("content-type must not be null!");
			}
			this.contentType = contentType;
			String path = "";
			boolean classpath = false;
			if (file != null) {
				classpath = file.startsWith(SslContextUtil.CLASSPATH_SCHEME);
				if (classpath) {
					path = file.substring(SslContextUtil.CLASSPATH_SCHEME.length());
					LOGGER.info("Load {} from classpath", path);
				} else {
					path = file;
					File f = new File(path);
					if (f.isFile() && f.canRead()) {
						LOGGER.info("Load {} from file-system", path);
					} else {
						path = "src/main/resources/" + file;
						f = new File(path);
						if (f.isFile() && f.canRead()) {
							LOGGER.info("Load {} from file-system", path);
						} else {
							path = file;
							InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
							if (in != null) {
								classpath = true;
								LOGGER.info("Load {} from classpath", path);
								try {
									in.close();
								} catch (IOException e) {
								}
							}
						}
					}
				}
			}
			this.classpath = classpath;
			this.path = path;
			if (this.classpath) {
				this.reload = false;
			} else {
				this.reload = reload;
			}
			load();
		}

		public void load() {
			byte[] data = Bytes.EMPTY;
			if (path.isEmpty()) {
				LOGGER.info("Empty {} file", contentType);
			} else {
				InputStream inStream;
				try {
					if (classpath) {
						inStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
					} else {
						inStream = new FileInputStream(path);
					}
					if (inStream != null) {
						try {
							ByteArrayOutputStream out = new ByteArrayOutputStream(8192);
							byte[] temp = new byte[4096];
							int length;
							while ((length = inStream.read(temp)) > 0) {
								out.write(temp, 0, length);
							}
							data = out.toByteArray();
							LOGGER.info("{}: {} file {} bytes", path, contentType, data.length);
						} catch (IOException ex) {
							LOGGER.info("Failure loading file {}", path, ex);
						} finally {
							try {
								inStream.close();
							} catch (IOException e) {
							}
						}
					}
				} catch (FileNotFoundException e1) {
					LOGGER.info("Failure loading file {}", path, e1);
				}
			}
			this.data = data;
		}

		public void handle(final HttpExchange httpExchange) throws IOException {
			final URI uri = httpExchange.getRequestURI();
			LOGGER.info("file-request: {} {}", httpExchange.getRequestMethod(), uri);
			String contentType = null;
			byte[] payload = null;
			int httpCode = 404;
			if (strictPathCheck(httpExchange)) {
				String method = httpExchange.getRequestMethod();
				if (method.equals("GET")) {
					if (reload) {
						load();
					}
					if (EtagGenerator.setEtag(httpExchange, data)) {
						httpCode = 304;
					} else {
						httpCode = 200;
						payload = data;
					}
					contentType = this.contentType;
					if (reload) {
						httpExchange.getResponseHeaders().add("Cache-Control", "no-cache");
					}
				} else if (method.equals("HEAD")) {
					contentType = this.contentType;
					payload = data;
					httpCode = 200;
					if (reload) {
						httpExchange.getResponseHeaders().add("Cache-Control", "no-cache");
					}
				} else {
					httpCode = 405;
				}
			}
			respond(httpExchange, httpCode, contentType, payload);
		}
	}

	/**
	 * HTTP handler for coap-resource.
	 */
	public static class CoapProxyHandler implements HttpHandler {

		private final MessageDeliverer messageDeliverer;
		private final Executor executor;
		private final String[] prefix;
		private final Principal anonymous;

		public CoapProxyHandler(MessageDeliverer messageDeliverer, Executor executor, String... prefix) {
			this.messageDeliverer = messageDeliverer;
			this.executor = executor;
			this.prefix = prefix;
			this.anonymous = null;
		}

		public CoapProxyHandler(MessageDeliverer messageDeliverer, Principal anonymous, Executor executor,
				String... prefix) {
			this.messageDeliverer = messageDeliverer;
			this.executor = executor;
			this.prefix = prefix;
			this.anonymous = anonymous;
		}

		public void fillUri(OptionSet options, String uri) {
			String[] prefix = this.prefix;
			String[] path = uri.split("/");
			int index = 0;
			for (index = 0; index < path.length - 1; ++index) {
				String element = path[index + 1];
				if (prefix != null && index < prefix.length) {
					String pre = prefix[index];
					if (pre.equals(element)) {
						continue;
					}
					prefix = null;
				}
				options.addUriPath(element);
			}
		}

		public boolean checkResourcePath(String path) {
			return true;
		}

		/**
		 * {@inheritDoc}
		 * 
		 * Simply transformation of http-get-request into coap-get-request.
		 */
		@Override
		public void handle(final HttpExchange httpExchange) throws IOException {
			final URI uri = httpExchange.getRequestURI();
			final String method = httpExchange.getRequestMethod();
			final Headers headers = httpExchange.getRequestHeaders();
			Request request = null;
			Principal principal = httpExchange.getPrincipal();
			Object attribute = httpExchange.getAttribute(ATTRIBUTE_PRINCIPAL);
			if (attribute instanceof Principal) {
				principal = (Principal) attribute;
			}
			if (principal == null) {
				principal = anonymous;
			}
			LOGGER.info("http-request: {} {} {}", method, uri, principal);
			logHeaders("request", headers);

			if (method.equals("GET") || method.equals("HEAD")) {
				request = Request.newGet();
				AddressEndpointContext context = new AddressEndpointContext(httpExchange.getRemoteAddress(), principal);
				request.setSourceContext(context);
			} else {
				// use ping to fail ...
				request = Request.newPing();
			}
			fillUri(request.getOptions(), uri.getPath());
			String coapPath = "/" + request.getOptions().getUriPathString();
			if (checkResourcePath(coapPath)) {
				Exchange coapExchange = new Exchange(request, httpExchange.getRemoteAddress(), Origin.REMOTE,
						executor) {

					@Override
					public void sendAccept() {
						// has no meaning for HTTP: do nothing
					}

					@Override
					public void sendReject() {
						Response response = Response.createResponse(getRequest(), ResponseCode.INTERNAL_SERVER_ERROR);
						sendResponse(response);
					}

					@Override
					public void sendResponse(Response response) {
						Request request = getRequest();
						if (response.getType() == null) {
							Type reqType = request.getType();
							if (request.acknowledge()) {
								response.setType(Type.ACK);
							} else {
								response.setType(reqType);
							}
						}
						request.setResponse(response);
						respond(httpExchange, response);
					}
				};
				messageDeliverer.deliverRequest(coapExchange);
			} else {
				int httpCode = 404;
				respond(httpExchange, httpCode, null, null);
				updateBan(httpExchange);
			}
		}

		public boolean respond(HttpExchange httpExchange, Response response) {
			LOGGER.info("CoAP response: {}", response);
			final URI uri = httpExchange.getRequestURI();
			String contentType = null;
			byte[] payload = response.getPayload();
			int httpCode = 200;
			if (response.isSuccess()) {
				if (response.getOptions().getContentFormat() == MediaTypeRegistry.APPLICATION_LINK_FORMAT) {
					Set<WebLink> links = LinkFormat.parse(response.getPayloadString());
					String path = uri.getPath();
					String title = path;
					int index = path.lastIndexOf('/');
					if (index >= 0) {
						title = path.substring(index + 1);
						path = path.substring(0, index + 1);
					}
					String page = HtmlGenerator.createListPage(path, "", title, links, null, Devices.ATTRIBUTE_TIME);
					payload = page.getBytes(StandardCharsets.UTF_8);
					contentType = "text/html; charset=utf-8";
				} else {
					contentType = "text/plain; charset=utf-8";
				}
				byte[] etag = response.getOptions().getResponseEtag();
				if (etag != null) {
					httpExchange.getResponseHeaders().set("ETag", StringUtil.byteArray2Hex(etag));
				}
			} else {
				payload = null;
				switch (response.getCode()) {
				case BAD_REQUEST:
					httpCode = 400;
					break;
				case UNAUTHORIZED:
					httpCode = 401;
					break;
				case BAD_OPTION:
					httpCode = 402;
					break;
				case FORBIDDEN:
					httpCode = 403;
					break;
				case NOT_FOUND:
					httpCode = 404;
					break;
				case METHOD_NOT_ALLOWED:
					httpCode = 405;
					break;
				case REQUEST_ENTITY_TOO_LARGE:
					httpCode = 413;
					break;
				default:
					httpCode = 500;
					break;
				}
			}
			try {
				respond(httpExchange, httpCode, contentType, payload);
				LOGGER.info("HTTP returned {}", response);
			} catch (IOException e) {
				LOGGER.warn("write response to {} failed!", httpExchange.getRemoteAddress(), e);
			}
			updateBan(httpExchange);
			return true;
		}

		public void respond(HttpExchange httpExchange, int httpCode, String contentType, byte[] payload)
				throws IOException {
			HttpService.respond(httpExchange, httpCode, contentType, payload);
		}

		public boolean updateBan(final HttpExchange httpExchange) {
			return true;
		}
	}

	/**
	 * Creates {@link CredentialsStore} from "lets encrypt path".
	 * <p>
	 * Appends {@link #HTTPS_PRIVATE_KEY} and {@link #HTTPS_FULL_CHAIN} to the
	 * provided path to load credentials.
	 * 
	 * @param credentialsPath path to lets encrypt credentials
	 * @param password64 base64 encoded password of credentials. May be
	 *            {@code null}, if credentials are not encrypted.
	 * @return created credentials store
	 * @throws IOException if an i/o error occurs
	 * @throws GeneralSecurityException if an encryption error occurs.
	 */
	public static CredentialsStore loadCredentials(String credentialsPath, String password64)
			throws IOException, GeneralSecurityException {
		if (credentialsPath.endsWith("/")) {
			credentialsPath = credentialsPath.substring(0, credentialsPath.length() - 1);
		}
		String privateKey = credentialsPath + "/" + HTTPS_PRIVATE_KEY;
		String fullChain = credentialsPath + "/" + HTTPS_FULL_CHAIN;
		File directory = new File(credentialsPath);
		if (!directory.exists()) {
			LOGGER.error("Missing directory {} for https credentials!", credentialsPath);
		} else {
			File file = new File(fullChain);
			if (!file.exists()) {
				LOGGER.error("Missing https full-chain {}!", fullChain);
			} else if (!file.canRead()) {
				LOGGER.error("Missing read permission for https full-chain {}!", fullChain);
			}
			file = new File(privateKey);
			if (!file.exists()) {
				LOGGER.error("Missing https private-key {}!", privateKey);
			} else if (!file.canRead()) {
				LOGGER.error("Missing read permission for https private-key {}!", privateKey);
			}
		}
		CredentialsStore credentialsStore = new CredentialsStore() {

			/**
			 * {@inheritDoc}
			 * 
			 * Add check for certificate chain.
			 */
			@Override
			protected boolean complete(Credentials newCredentials) {
				return super.complete(newCredentials) && newCredentials.hasCertificateChain();
			}
		};
		credentialsStore.setTag("https ");
		credentialsStore.loadAndCreateMonitor(password64, true, fullChain, privateKey);
		return credentialsStore;
	}

	public static HttpService getHttpService() {
		return httpService;
	}

	/**
	 * Creates http service.
	 * 
	 * @param httpsPort server poet
	 * @param credentialsPath server credentials
	 * @param password64 base64 encoded password of credentials. May be
	 *            {@code null}, if credentials are not encrypted.
	 * @param tls12Only use TLS 1.2 only
	 * @return {@code true} on success, {@code false} otherwise.
	 */
	public static boolean createHttpService(int httpsPort, String credentialsPath, String password64,
			boolean tls12Only) {
		try {
			CredentialsStore credentials = loadCredentials(credentialsPath, password64);
			HttpService service = new HttpService(new InetSocketAddress(httpsPort), credentials,
					tls12Only ? TLS_1_2 : TLS, tls12Only ? TLS_PROTOCOLS_1_2_ONLY : TLS_PROTOCOLS);
			httpService = service;
			return true;
		} catch (IOException e) {
			LOGGER.error("I/O error", e);
		} catch (GeneralSecurityException e) {
			LOGGER.error("Crypto error", e);
		}
		return false;
	}

	/**
	 * Starts http service.
	 * 
	 * @return {@code true}, if started, {@code false}, if no http service was
	 *         created.
	 * @see #createHttpService(int, String, String, boolean)
	 * @see #stopHttpService()
	 */
	public static boolean startHttpService() {
		HttpService service = httpService;
		if (service != null) {
			service.start();
			return true;
		} else {
			LOGGER.error("HTTP service missing!");
			return false;
		}
	}

	/**
	 * Stops http service.
	 * 
	 * @return {@code true}, if stopped, {@code false}, if no http service was
	 *         created.
	 * @see #createHttpService(int, String, String, boolean)
	 * @see #startHttpService()
	 */
	public static boolean stopHttpService() {
		HttpService service = httpService;
		if (service != null) {
			service.stop();
			return true;
		} else {
			LOGGER.error("HTTP service missing!");
			return false;
		}
	}
}
