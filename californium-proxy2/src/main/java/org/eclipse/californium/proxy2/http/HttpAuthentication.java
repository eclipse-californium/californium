/********************************************************************************
 * Copyright (c) 2025 Contributors to the Eclipse Foundation
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
package org.eclipse.californium.proxy2.http;

import java.net.URI;
import java.util.Arrays;

import org.apache.hc.client5.http.ContextBuilder;
import org.apache.hc.client5.http.auth.CredentialsProvider;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.auth.CredentialsProviderBuilder;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.message.BasicHeader;

import com.google.common.net.HttpHeaders;

/**
 * Http authentication.
 * <p>
 * Supported authentication options.
 * 
 * <dl>
 * <dt>Bearer {@code <access-token>}</dt>
 * <dd>adds the {@code <access-token>} preemptive to the request's headers</dd>
 * <dt>PreBasic {@code <username:password>}</dt>
 * <dd>Uses BASIC authentication preemptive</dd>
 * <dt>Header {@code <name:value>}</dt>
 * <dd>Uses a header with name-value pair</dd>
 * <dt>{@code <username:password>}</dt>
 * <dd>Prepares to respond to a {@code WWW-Authenticate} challenge from the
 * server.</dd>
 * </dl>
 * 
 * e.g.:
 * <ul>
 * <li>{@code "Bearer abcdefghijklmnopqrstuvwxyz.token.1234567890"}</li>
 * <li>{@code "PreBasic me:secret"}</li>
 * <li>{@code "Header auth: abcdefghijklmnopqrstuvwxyz"}</li>
 * <li>{@code "me:secret"}</li>
 * </ul>
 * 
 * The value is passed in as argument in
 * {@link #HttpAuthentication(URI, String)}. It is the translated either in
 * {@link #getExtraHeader()} or {@link #getHttpClientContext()}.
 * 
 * @since 4.0
 */
public class HttpAuthentication {

	private static final String AUTH_BEARER = "Bearer ";
	private static final String AUTH_PREEMPTIVE_BASIC = "PreBasic ";
	private static final String AUTH_HEADER = "Header ";

	private final HttpClientContext context;
	private final Header extra;

	/**
	 * Creates http authentication.
	 * <p>
	 * Supported authentication options.
	 * 
	 * <dl>
	 * <dt>Bearer {@code <access-token>}</dt>
	 * <dd>adds the {@code <access-token>} preemptive to the request's
	 * headers</dd>
	 * <dt>PreBasic {@code <username:password>}</dt>
	 * <dd>Uses BASIC authentication preemptive</dd>
	 * <dt>Header {@code <name:value>}</dt>
	 * <dd>Uses a header with name-value pair</dd>
	 * <dt>{@code <username:password>}</dt>
	 * <dd>Prepares to respond to a {@code WWW-Authenticate} challenge from the
	 * server.</dd>
	 * </dl>
	 * 
	 * e.g.:
	 * <ul>
	 * <li>{@code "Bearer abcdefghijklmnopqrstuvwxyz.token.1234567890"}</li>
	 * <li>{@code "PreBasic me:secret"}</li>
	 * <li>{@code "Header auth: abcdefghijklmnopqrstuvwxyz"}</li>
	 * <li>{@code "me:secret"}</li>
	 * </ul>
	 * 
	 * that value is passed in as authentication argument.
	 * 
	 * @param destination http destination. Used to limit the usage of the
	 *            credentials to that destination
	 * @param authentication http authentication. Maybe {@code null}, if not
	 *            authentication is used.
	 */
	public HttpAuthentication(URI destination, String authentication) {
		HttpClientContext context = null;
		Header extra = null;

		if (authentication != null) {
			if (authentication.regionMatches(true, 0, AUTH_BEARER, 0, AUTH_BEARER.length())) {
				extra = new BasicHeader(HttpHeaders.AUTHORIZATION, authentication);
			} else if (authentication.regionMatches(true, 0, AUTH_PREEMPTIVE_BASIC, 0,
					AUTH_PREEMPTIVE_BASIC.length())) {
				UsernamePasswordCredentials credentials = parseCredentials(authentication,
						AUTH_PREEMPTIVE_BASIC.length());
				if (credentials != null) {
					context = ContextBuilder.create().preemptiveBasicAuth(getTargetHost(destination), credentials)
							.build();
				}
			} else if (authentication.regionMatches(true, 0, AUTH_HEADER, 0, AUTH_HEADER.length())) {
				extra = parseHeader(authentication, AUTH_HEADER.length());
			} else {
				UsernamePasswordCredentials credentials = parseCredentials(authentication, 0);
				if (credentials != null) {
					CredentialsProvider credentialsProvider = CredentialsProviderBuilder.create()
							.add(getTargetHost(destination), credentials).build();
					context = ContextBuilder.create().useCredentialsProvider(credentialsProvider).build();
				}
			}
		}
		this.context = context;
		this.extra = extra;
	}

	/**
	 * Parses credentials from authentication.
	 * 
	 * @param authentication authentication as string. Expects
	 *            {@code <username>:<password>}
	 * @param offset offset to parse the credentials.
	 * @return UsernamePasswordCredentials on success, {@code null}, if parsing
	 *         the credentials fails.
	 */
	private UsernamePasswordCredentials parseCredentials(String authentication, int offset) {
		int index = authentication.indexOf(':', offset);
		if (index > 0) {
			char[] pw = authentication.toCharArray();
			pw = Arrays.copyOfRange(pw, index + 1, pw.length);

			return new UsernamePasswordCredentials(authentication.substring(offset, index).trim(), pw);
		}
		return null;
	}

	/**
	 * Parses http-header from authentication.
	 * 
	 * @param authentication authentication as string. Expects
	 *            {@code <name>:<value>}
	 * @param offset offset to parse the credentials.
	 * @return Header on success, {@code null}, if parsing fails.
	 */
	private Header parseHeader(String authentication, int offset) {
		int index = authentication.indexOf(':', offset);
		if (index > 0) {
			String name = authentication.substring(offset, index).trim();
			String value = authentication.substring(index + 1);
			return new BasicHeader(name, value);
		}
		return null;
	}

	/**
	 * Creates target host from destination URI.
	 * 
	 * @param destination destination URI
	 * @return target host
	 */
	private HttpHost getTargetHost(URI destination) {
		return new HttpHost(destination.getScheme(), destination.getHost(), destination.getPort());
	}

	/**
	 * Gets extra header for authentication.
	 * 
	 * @return extra header for authentication or {@code null}, if not used.
	 */
	public Header getExtraHeader() {
		return extra;
	}

	/**
	 * Gets http client context for authentication.
	 * 
	 * @return http client context for authentication or {@code null}, if not
	 *         used.
	 */
	public HttpClientContext getHttpClientContext() {
		return context;
	}
}
