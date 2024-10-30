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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/

package org.eclipse.californium.examples;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.Message;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.http.nio.support.AsyncResponseBuilder;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.proxy2.config.Proxy2Config;
import org.eclipse.californium.proxy2.http.ContentTypedEntity;
import org.eclipse.californium.proxy2.http.server.ByteBufferAsyncServerRequestHandler;
import org.eclipse.californium.proxy2.http.server.HttpServer;

import com.google.common.net.HttpHeaders;

/**
 * Example HTTP server for proxy demonstration.
 * 
 * {@code http://localhost:8000/http-target}
 */
public class ExampleHttpServer {

	/**
	 * File name for configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumHttpDemo3.properties");
	/**
	 * Header for configuration.
	 */
	private static final String CONFIG_HEADER = "Californium HTTP Properties file for Proxy Demo-Server";

	public static final ThreadGroup HTTP_THREAD_GROUP = new ThreadGroup("http"); //$NON-NLS-1$

	public static final int DEFAULT_PORT = 8000;
	public static final String RESOURCE = "/http-target";
	public static final String RESOURCE_EMPTY = "/http-empty";

	static {
		Proxy2Config.register();
	}

	private SimpleCounterStatistic requests = new SimpleCounterStatistic("http-requests");
	private AtomicLong requestCounter = new AtomicLong();
	private long lastRequestCounterSync;

	public ExampleHttpServer(Configuration config, final int httpPort) throws IOException {
		HttpServer server = new HttpServer(config, httpPort);
		server.setSimpleResource(RESOURCE, "Hi! I am the Http Server on %s. Request %d.", requestCounter);
		server.register(RESOURCE_EMPTY, new ByteBufferAsyncServerRequestHandler() {

			@Override
			public void handle(Message<HttpRequest, ContentTypedEntity> requestObject, ResponseTrigger responseTrigger,
					HttpContext context) throws HttpException, IOException {
				responseTrigger.submitResponse(AsyncResponseBuilder.create(HttpStatus.SC_OK).build(), context);
			}

		});
		server.register("/basic", new AuthenticatingRequestHandler(false));
		server.register("/digest", new AuthenticatingRequestHandler(true));

		server.setSimpleResource("*", "Example Http server on %s.", null);
		server.start();
		System.out.println("==================================================");
		System.out.println("== Started HTTP server on port " + httpPort);
		System.out.println("== Request: http://<host>:" + httpPort + RESOURCE);
		System.out.println("==================================================");
	}

	public void dumpStatistic() {
		long count = requestCounter.get();
		if (count > 0) {
			long delta = count - lastRequestCounterSync;
			lastRequestCounterSync = count;
			if (delta > 0) {
				requests.increment((int) delta);
			}
			System.out.println(requests.dump(0));
		}
	}

	public static Configuration init() {
		return Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, null);
	}

	public static void main(String arg[]) throws IOException {
		// NetworkConfig HTTP_PORT is used for proxy
		Configuration config = init();
		int port = DEFAULT_PORT;
		if (arg.length > 0) {
			port = Integer.parseInt(arg[0]);
		}
		final ExampleHttpServer server = new ExampleHttpServer(config, port);
		ScheduledExecutorService executor = ExecutorsUtil
				.newSingleThreadScheduledExecutor(new NamedThreadFactory("statistic"));
		executor.scheduleAtFixedRate(new Runnable() {

			@Override
			public void run() {
				server.dumpStatistic();
			}
		}, 10, 10, TimeUnit.SECONDS);
	}

	/**
	 * Handler ensuring authorization.
	 * 
	 * Using {@link HttpHeaders#WWW_AUTHENTICATE} response, if
	 * {@link HttpHeaders#AUTHORIZATION} is missing.
	 * 
	 * If {@link HttpHeaders#AUTHORIZATION} is provided, this isn't further
	 * validated.
	 * 
	 * @since 4.0
	 */
	private static class AuthenticatingRequestHandler extends ByteBufferAsyncServerRequestHandler {

		/**
		 * If {@code true}, requests DIGEST authentication instead of BASIC.
		 */
		private final boolean digest;

		/**
		 * Create authenticating request handler.
		 * 
		 * @param digest {@code true} requests DIGEST authentication,
		 *            {@code false} for BASIC authentication.
		 */
		private AuthenticatingRequestHandler(boolean digest) {
			this.digest = digest;
		}

		@Override
		public void handle(final Message<HttpRequest, ContentTypedEntity> message,
				final ResponseTrigger responseTrigger, final HttpContext context) throws HttpException, IOException {

			try {
				HttpRequest head = message.getHead();
				System.out.println(head.getMethod() + " - " + head.getUri());
				Header authorization = null;
				Header[] headers = head.getHeaders();
				for (Header header : headers) {
					System.out.println("   " + header);
					if (header.getName().equals(HttpHeaders.AUTHORIZATION)) {
						authorization = header;
					}
				}
				ContentTypedEntity body = message.getBody();
				if (body != null) {
					System.out.println(body.getContentType() + " " + body.getContent().length + " bytes");
					String mimeType = body.getContentType().getMimeType();
					if (mimeType.equals("text/plain") || mimeType.equals("text/xml")
							|| mimeType.equals("application/json") || mimeType.equals("application/xml")) {
						System.out.println(new String(body.getContent(), body.getContentType().getCharset()));
					}
				}
				if (authorization == null) {
					System.out.println("   ==> not authorized, " + HttpHeaders.WWW_AUTHENTICATE);
					String authSchem;
					if (digest) {
						byte[] nonce = new byte[15];
						byte[] opaque = new byte[9];
						SecureRandom random = new SecureRandom();
						random.nextBytes(nonce);
						random.nextBytes(opaque);

						authSchem = "Digest realm=\"echo@test\", qop=\"auth,auth-int\", algorithm=SHA-256, "
								+ "nonce=\"" + StringUtil.byteArrayToBase64(nonce) + "\", " + "opaque=\""
								+ StringUtil.byteArrayToBase64(opaque) + "\"";
					} else {
						authSchem = "Basic realm=\"echo@test\", charset=\"UTF-8\"";
					}
					System.out.println("   " + authSchem);
					Header authenticate = new BasicHeader(HttpHeaders.WWW_AUTHENTICATE, authSchem);
					responseTrigger.submitResponse(
							AsyncResponseBuilder.create(HttpStatus.SC_UNAUTHORIZED).addHeader(authenticate).build(),
							context);
					return;
				}
				if (body != null) {
					int hc = Arrays.hashCode(body.getContent());
					responseTrigger.submitResponse(AsyncResponseBuilder.create(HttpStatus.SC_OK)
							.addHeader(HttpHeaders.ETAG, Integer.toHexString(hc))
							.setEntity(body.getContent(), body.getContentType()).build(), context);
				} else {
					responseTrigger.submitResponse(AsyncResponseBuilder.create(HttpStatus.SC_OK).build(), context);
				}
			} catch (URISyntaxException e) {
				String payload = e.getReason();
				responseTrigger.submitResponse(AsyncResponseBuilder.create(HttpStatus.SC_BAD_REQUEST)
						.setEntity(payload, ContentType.TEXT_PLAIN.withCharset(UTF_8)).build(), context);
			}
		}

	}
}
