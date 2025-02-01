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
package org.eclipse.californium.cloud.s3.http;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.Principal;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.eclipse.californium.cloud.http.HttpService;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.util.DomainPrincipalInfo;
import org.eclipse.californium.cloud.s3.util.DomainPrincipalInfoProvider;
import org.eclipse.californium.cloud.s3.util.DomainNamePair;
import org.eclipse.californium.cloud.s3.util.WebAppDomainUser;
import org.eclipse.californium.cloud.s3.util.WebAppUser;
import org.eclipse.californium.cloud.s3.util.WebAppUserProvider;
import org.eclipse.californium.cloud.util.PrincipalInfo.Type;
import org.eclipse.californium.cloud.util.PrincipalInfo;
import org.eclipse.californium.elements.auth.AdditionalInfo;
import org.eclipse.californium.elements.auth.ExtensiblePrincipal;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.LeastRecentlyUpdatedCache;
import org.eclipse.californium.elements.util.LeastRecentlyUpdatedCache.Timestamped;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalMac;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalMessageDigest;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

/**
 * AWS4-HMAC-SHA256 signature verifier.
 * 
 * @since 3.12
 */
@SuppressWarnings("restriction")
public class Aws4Authorizer {

	/**
	 * Logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(Aws4Authorizer.class);

	/**
	 * Pair of id and value.
	 */
	private static class Pair implements Comparable<Pair> {

		/**
		 * ID.
		 */
		private final String id;
		/**
		 * Value.
		 */
		private final String value;

		/**
		 * Create id-value pair.
		 * 
		 * @param id ID
		 * @param value value
		 */
		private Pair(String id, String value) {
			this.id = id;
			this.value = value;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = id.hashCode();
			result = prime * result + ((value == null) ? 0 : value.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			Pair other = (Pair) obj;
			if (!id.equals(other.id))
				return false;
			if (value == null) {
				if (other.value != null)
					return false;
			} else if (!value.equals(other.value))
				return false;
			return true;
		}

		@Override
		public int compareTo(Pair o) {
			return id.compareTo(o.id);
		}
	}

	private static final DomainPrincipalInfoProvider webPrincipalInfoProvider = new DomainPrincipalInfoProvider() {

		@Override
		public DomainPrincipalInfo getPrincipalInfo(Principal principal) {
			if (principal instanceof WebAppAuthorization) {
				WebAppAuthorization authorization = (WebAppAuthorization) principal;
				List<String> groups = authorization.getWebAppUser().groups;
				String group = groups.isEmpty() ? "web" : groups.get(0);
				return new DomainPrincipalInfo(authorization.getDomain(), group, authorization.getName(), Type.WEB);
			}
			return null;
		}
	};

	/**
	 * Web application authorization.
	 */
	public static class Authorization implements Principal {

		/**
		 * Name from http Credential attribute. (Access API key ID).
		 */
		private final String name;
		/**
		 * List of elements from http Credential attribute building the scope.
		 */
		private final List<String> scope;
		/**
		 * List of signed headers from http SignedHeaders attribute.
		 */
		private final List<String> signedHeaders;
		/**
		 * Signature from http Signature attribute.
		 */
		private final String signature;
		/**
		 * Date and time from the http header.
		 */
		private final String dateTime;
		/**
		 * Indicates, that the http request was received in time
		 * ({@code -30s to +10s} according the {@link #dateTime}).
		 */
		private final boolean inTime;
		/**
		 * Indicates, that the signature of the http Signature attribute is the
		 * same as the calculated one.
		 */
		private boolean verified;

		/**
		 * Creates authorization instance from http exchange.
		 * 
		 * @param httpExchange http exchange to extract the authorization info
		 */
		public Authorization(final HttpExchange httpExchange) {
			Headers headers = httpExchange.getRequestHeaders();
			String authorization = headers.getFirst("Authorization");
			String name = null;
			String signature = null;
			List<String> scope = null;
			List<String> signedHeaders = null;
			boolean inTime = false;
			if (authorization != null) {
				LOGGER.debug("Authorization {}", authorization);
				int algoLength = AWS_ALGORITHM.length();
				if (authorization.startsWith(AWS_ALGORITHM) && authorization.charAt(algoLength) == ' ') {
					String[] fields = authorization.substring(algoLength + 1).split(",");
					for (String field : fields) {
						if (field.startsWith("Credential=")) {
							String[] creds = field.substring("Credential=".length()).split("/");
							name = creds[0];
							scope = new ArrayList<>(creds.length - 1);
							for (int index = 1; index < creds.length; ++index) {
								scope.add(creds[index]);
							}
							scope = Collections.unmodifiableList(scope);
						} else if (field.startsWith("SignedHeaders=")) {
							signedHeaders = Arrays.asList(field.substring("SignedHeaders=".length()).split(";"));
						} else if (field.startsWith("Signature=")) {
							signature = field.substring("Signature=".length());
						}
					}
				}
			}
			this.name = name;
			this.scope = scope;
			this.signedHeaders = signedHeaders;
			this.signature = signature;
			this.dateTime = headers.getFirst(AWS_HEADER_DATE);
			if (dateTime != null) {
				long now = System.currentTimeMillis();
				String start = formatDateTime(now - TimeUnit.SECONDS.toMillis(30));
				String end = formatDateTime(now + TimeUnit.SECONDS.toMillis(10));
				if (dateTime.compareTo(start) < 0) {
					LOGGER.info("Request: invalid time {} before {}", dateTime, start);
				} else if (dateTime.compareTo(end) > 0) {
					LOGGER.info("Request: invalid time {} after {}", dateTime, end);
				} else if (scope != null && !scope.isEmpty()) {
					String date = scope.get(0);
					start = start.substring(0, 8);
					end = end.substring(0, 8);
					if (date.compareTo(start) < 0) {
						LOGGER.info("Scope: invalid date {} before {}", date, start);
					} else if (date.compareTo(end) > 0) {
						LOGGER.info("Scope: invalid date {} after {}", date, end);
					} else {
						inTime = true;
					}
				}
			}
			this.inTime = inTime;
		}

		/**
		 * Initializes instance from other instance.
		 * 
		 * @param authorization other instance to copy fields
		 * @throws NullPointerException if authorization is {@code null}
		 */
		protected Authorization(Authorization authorization) {
			if (authorization == null) {
				throw new NullPointerException("authorization must not be null!");
			}
			this.name = authorization.name;
			this.scope = authorization.scope;
			this.signedHeaders = authorization.signedHeaders;
			this.signature = authorization.signature;
			this.dateTime = authorization.dateTime;
			this.inTime = authorization.inTime;
		}

		/**
		 * Gets name from http Credential attribute.
		 * 
		 * @return name from http Credential attribute
		 */
		@Override
		public String getName() {
			return name;
		}

		@Override
		public int hashCode() {
			return name.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			Authorization other = (Authorization) obj;
			if (name == null) {
				if (other.name != null)
					return false;
			} else if (!name.equals(other.name))
				return false;
			return true;
		}

		@Override
		public String toString() {
			return name;
		}

		/**
		 * Gets signature from http Signature attribute.
		 * 
		 * @return signature from http Signature attribute
		 */
		public String getSignature() {
			return signature;
		}

		/**
		 * Verifies provided calculated signature matches the signature in the
		 * http headers.
		 * 
		 * @param signature calculated signature
		 * @return {@code true}, if matching, {@code false}, otherwise.
		 * @see #isVerified()
		 */
		public boolean verify(String signature) {
			boolean verified = true;
			if (signature == null || !signature.equals(this.signature)) {
				verified = false;
			} else if (name == null || name.isEmpty()) {
				verified = false;
			} else if (scope == null || scope.size() < 4) {
				verified = false;
			} else if (signedHeaders == null || signedHeaders.isEmpty()) {
				verified = false;
			}
			this.verified = verified;
			return verified;
		}

		/**
		 * Indicates, if the signature is verified.
		 * <p>
		 * Requires to execute {@link #verify(String)} before.
		 * 
		 * @return {@code true}, if matching, {@code false}, otherwise.
		 * @see #verify(String)
		 */
		public boolean isVerified() {
			return verified;
		}

		/**
		 * Gets date and time from the http header.
		 * 
		 * @return date and time from the http header
		 */
		public String getDateTime() {
			return dateTime;
		}

		/**
		 * Indicates, that the http request was received in time
		 * ({@code -30s to +10s} according the {@link #getDateTime()}).
		 * 
		 * @return {@code true}, if the http request was received in time,
		 *         {@code false}, otherwise.
		 */
		public boolean isInTime() {
			return inTime;
		}

		/**
		 * Checks scope of signature.
		 * 
		 * @param region region
		 * @return {@code true}, if the signature contains the expected scope,
		 *         {@code false}, otherwise.
		 */
		public boolean isInScope(String region) {
			if (scope != null && scope.size() == 4) {
				return region.equals(scope.get(1)) && "s3".equals(scope.get(2)) && "aws4_request".equals(scope.get(3));
			}
			return false;
		}

		/**
		 * Gets list of elements from http Credential attribute building the
		 * scope.
		 * 
		 * @return list of elements from http Credential attribute building the
		 *         scope.
		 */
		public List<String> getScope() {
			return scope;
		}

		/**
		 * Gets list of signed headers from http SignedHeaders attribute.
		 * 
		 * @return list of signed headers from http SignedHeaders attribute.
		 * 
		 */
		public List<String> getSignedHeaders() {
			return signedHeaders;
		}

		/**
		 * Creates a web application authorization including specific
		 * permissions of the associated web user.
		 * 
		 * @param domain domain name
		 * @param webAppUser web-app user
		 * @return web application authorization
		 * @throws NullPointerException if any parameter is {@code null}
		 */
		public WebAppAuthorization createWebAppAuthorization(String domain, WebAppUser webAppUser) {
			return new WebAppAuthorization(this, domain, webAppUser);
		}
	}

	/**
	 * Web application authorization.
	 */
	public static class WebAppAuthorization extends Authorization implements ExtensiblePrincipal<WebAppAuthorization> {

		private AdditionalInfo additionalInfo;

		/**
		 * The domain name of the associated web application user.
		 */
		private String domain;
		/**
		 * The web application user.
		 */
		private WebAppUser webAppUser;

		/**
		 * Creates a web application authorization instance.
		 * 
		 * @param authorization http authorization
		 * @param domain domain name
		 * @param webAppUser web application user
		 * @throws NullPointerException if any parameter is {@code null}
		 */
		public WebAppAuthorization(Authorization authorization, String domain, WebAppUser webAppUser) {
			super(authorization);
			if (domain == null) {
				throw new NullPointerException("domain must not be null!");
			}
			if (webAppUser == null) {
				throw new NullPointerException("webAppUser must not be null!");
			}
			this.domain = domain;
			this.webAppUser = webAppUser;
			Map<String, Object> info = new HashMap<>();
			info.put(PrincipalInfo.INFO_NAME, authorization.getName());
			info.put(PrincipalInfo.INFO_PROVIDER, webPrincipalInfoProvider);
			info.put(DomainPrincipalInfo.INFO_DOMAIN, domain);
			this.additionalInfo = AdditionalInfo.from(info);
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = super.hashCode();
			result = prime * result + ((domain == null) ? 0 : domain.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (!super.equals(obj)) {
				return false;
			}
			WebAppAuthorization other = (WebAppAuthorization) obj;
			if (domain == null) {
				if (other.domain != null)
					return false;
			} else if (!domain.equals(other.domain))
				return false;
			return true;
		}

		@Override
		public String toString() {
			return super.toString() + "@" + domain;
		}

		/**
		 * Gets web application user.
		 * 
		 * @return web application user
		 */
		public WebAppUser getWebAppUser() {
			return webAppUser;
		}

		/**
		 * Gets domain name of the associated web application user.
		 * 
		 * @return domain name of the associated web application user
		 */
		public String getDomain() {
			return domain;
		}

		@Override
		public WebAppAuthorization amend(AdditionalInfo additionalInfo) {
			this.additionalInfo = additionalInfo;
			return null;
		}

		@Override
		public AdditionalInfo getExtendedInfo() {
			return additionalInfo;
		}

		@Override
		public boolean isAnonymous() {
			return false;
		}
	}

	/**
	 * HMAC algorithm for AWS4-HMAC-SHA256.
	 */
	private static final String HMAC_ALGORITHM = "HmacSHA256";
	/**
	 * Thread-local MAC.
	 */
	private static final ThreadLocalMac MAC = new ThreadLocalMac(HMAC_ALGORITHM);

	/**
	 * Hash algorithm for AWS4-HMAC-SHA256.
	 */
	private static final String HASH_ALGORITHM = "SHA-256";
	/**
	 * Thread-local MessageDigest.
	 */
	private static final ThreadLocalMessageDigest HASH = new ThreadLocalMessageDigest(HASH_ALGORITHM);

	/**
	 * Regular expression pattern for replacing characters according the
	 * AWS4-HMAC-SHA256 encoding rules.
	 */
	private static final Pattern AWS_ENCODE_PATTERN = Pattern.compile("\\+|\\*|%7E|%2F");

	/**
	 * Http reqeust signature algorithm.
	 */
	private static final String AWS_ALGORITHM = "AWS4-HMAC-SHA256";
	/**
	 * Http header for date and time.
	 */
	private static final String AWS_HEADER_DATE = "x-amz-date";
	/**
	 * Http header for content hash.
	 */
	private static final String AWS_HEADER_CONTENT_SHA256 = "x-amz-content-sha256";

	/**
	 * Web application user provider.
	 */
	private final WebAppUserProvider webAppUserProvider;
	/**
	 * S3 region.
	 */
	private final String region;
	/**
	 * Ban store for latest failing authentications.
	 */
	private final LeastRecentlyUpdatedCache<InetAddress, AtomicInteger> banStore = new LeastRecentlyUpdatedCache<>(100,
			1000, 2, TimeUnit.MINUTES);

	/**
	 * Create AWS4-HMAC-SHA256 signature verifier.
	 * <p>
	 * The S3 region must be the fixed region used in javascript app to send
	 * request to the http-host, for the provided javascript app use
	 * {@link S3ProxyClient#DEFAULT_REGION}.
	 * 
	 * @param webAppUserProvider web application user provider.
	 * @param region S3 region
	 * @throws NullPointerException if webAppUserProvider or region is
	 *             {@code null}.
	 */
	public Aws4Authorizer(WebAppUserProvider webAppUserProvider, String region) {
		if (webAppUserProvider == null) {
			throw new NullPointerException("Web application user provider must not be null!");
		}
		if (region == null) {
			throw new NullPointerException("region must not be null!");
		}
		this.webAppUserProvider = webAppUserProvider;
		this.region = region;
	}

	/**
	 * Check AWS4-HMAC-SHA256 signature of http request.
	 * 
	 * @param httpExchange http exchange
	 * @param banTag ban-tag
	 * @return authorization, or {@code null} in case of an internal error.
	 * @throws IOException if an i/o error occurs on sending a response
	 */
	public Authorization checkSignature(final HttpExchange httpExchange, String banTag) throws IOException {
		Authorization authorization = null;
		int httpCode = 401;
		try {
			LOGGER.debug("{} {} {}", banTag, httpExchange.getRequestMethod(), httpExchange.getRequestURI());
			authorization = new Authorization(httpExchange);
			String name = authorization.getName();
			if (name != null) {
				DomainNamePair domainName = DomainNamePair.fromName(name);
				WebAppDomainUser domainUser = webAppUserProvider.getDomainUser(domainName.domain, domainName.name);
				if (domainUser != null) {
					String requestSignature = calculateSignature(httpExchange, authorization, domainUser.user.password);
					if (!authorization.isInScope(region)) {
						LOGGER.warn("key {} not in scope! {}", name, authorization.getScope());
					} else if (authorization.verify(requestSignature)) {
						if (authorization.isInTime()) {
							banStore.remove(httpExchange.getRemoteAddress().getAddress());
						}
						LOGGER.debug("key {} verified.", name);
						return authorization.createWebAppAuthorization(domainUser.domain, domainUser.user);
					} else {
						LOGGER.warn("key {}", name);
						LOGGER.warn("{}", requestSignature);
						LOGGER.warn("{}", authorization.getSignature());
					}
				}
			}
		} catch (Throwable t) {
			LOGGER.warn("AWS4", t);
			httpCode = 500;
			HttpService.ban(httpExchange, banTag);
		}
		HttpService.respond(httpExchange, httpCode, null, null);
		return authorization;
	}

	/**
	 * Checks for recently failed authorization attempts.
	 * 
	 * @param httpExchange http exchange
	 * @return {@code true}, to process the request, {@code false}, if the
	 *         request is blocked.
	 * @throws IOException if an i/o error occurs on sending a response
	 */
	public boolean precheckBan(final HttpExchange httpExchange) throws IOException {
		final InetAddress remote = httpExchange.getRemoteAddress().getAddress();
		Timestamped<AtomicInteger> failure = banStore.getTimestamped(remote);
		if (failure != null && failure.getValue().get() > 2) {
			if (banStore.isStale(remote)) {
				banStore.remove(remote, failure.getValue());
			} else {
				long expire = banStore.getExpirationThreshold(TimeUnit.NANOSECONDS);
				long left = TimeUnit.NANOSECONDS.toSeconds(expire - ClockUtil.nanoRealtime() + failure.getLastUpdate());
				int httpCode = 429;
				String contentType = "text/html; charset=utf-8";
				String details = (left > 90) ? TimeUnit.SECONDS.toMinutes(left + 30) + " minutes" : left + " seconds";
				byte[] payload = ("<h1>" + httpCode + " - Too many retries! Wait for " + details + ".</h1>")
						.getBytes(StandardCharsets.UTF_8);
				httpExchange.getResponseHeaders().add("Retry-After", Long.toString(left));
				HttpService.respond(httpExchange, httpCode, contentType, payload);
				final Object logRemote = StringUtil.toLog(httpExchange.getRemoteAddress());
				LOGGER.info("aws4-response: {} {} from {}", httpCode, details, logRemote);
				return false;
			}
		}
		return true;
	}

	/**
	 * Update ban-store on the result of the http exchange.
	 * 
	 * @param httpExchange http exchange
	 * @return {@code true}, if the ban-store is updated, {@code false}, if the
	 *         ban-store is exceeded.
	 */
	public boolean updateBan(final HttpExchange httpExchange) {
		final InetAddress remote = httpExchange.getRemoteAddress().getAddress();
		if (httpExchange.getResponseCode() == 200) {
			banStore.remove(remote);
		} else if (httpExchange.getResponseCode() != 429) {
			Timestamped<AtomicInteger> failure = banStore.getTimestamped(remote);
			if (failure == null) {
				if (!banStore.put(remote, new AtomicInteger(1))) {
					// ban store exhausted
					return false;
				}
			} else {
				failure.getValue().incrementAndGet();
				banStore.update(remote);
			}
		}
		return true;
	}

	/**
	 * Calculate signature.
	 * 
	 * @param exchange http exchange
	 * @param authorization authorization from http exchange
	 * @param apiKeySecret API key secret
	 * @return calculated signature
	 * @throws InvalidKeyException if generated signature key is inappropriate.
	 */
	private String calculateSignature(HttpExchange exchange, Authorization authorization, String apiKeySecret)
			throws InvalidKeyException {
		StringBuilder request = new StringBuilder();
		request.append(exchange.getRequestMethod()).append("\n");
		URI uri = exchange.getRequestURI();
		request.append(urlEncoded(uri.getPath(), true)).append("\n");
		request.append(encodeQuery(uri.getQuery())).append("\n");
		request.append(encodeHeaders(exchange.getRequestHeaders(), authorization.getSignedHeaders())).append("\n");
		String dateTime = exchange.getRequestHeaders().getFirst(AWS_HEADER_DATE);
		String contentHash = exchange.getRequestHeaders().getFirst(AWS_HEADER_CONTENT_SHA256);
		if (contentHash == null) {
			contentHash = hash("");
		}
		request.append(contentHash);
		LOGGER.trace("Request: {}", request);
		String requestHash = hash(request.toString());

		StringBuilder stringToSign = new StringBuilder();
		stringToSign.append(AWS_ALGORITHM).append('\n');
		stringToSign.append(dateTime).append('\n');
		for (String element : authorization.getScope()) {
			stringToSign.append(element).append('/');
		}
		stringToSign.setLength(stringToSign.length() - 1);
		stringToSign.append('\n');
		stringToSign.append(requestHash);
		LOGGER.debug("StringtoSign: {}", stringToSign);

		byte[] key = getSigningKey(apiKeySecret, authorization.getScope());
		LOGGER.trace("KeyToSign: {}", StringUtil.byteArray2Hex(key).toLowerCase());

		key = hmac(key, stringToSign.toString());
		return StringUtil.byteArray2Hex(key).toLowerCase();
	}

	/**
	 * Get signing key.
	 * 
	 * @param apiKeySecret API key secret
	 * @param scope scope from request
	 * @return byte array with signing key.
	 * @throws InvalidKeyException if generated signature key is inappropriate.
	 */
	public static byte[] getSigningKey(String apiKeySecret, List<String> scope) throws InvalidKeyException {
		byte[] hashKey = ("AWS4" + apiKeySecret).getBytes(StandardCharsets.UTF_8);
		for (String element : scope) {
			LOGGER.trace("Append signing key: {}", element);
			hashKey = hmac(hashKey, element);
		}
		return hashKey;
	}

	/**
	 * Calculate hash of provided text.
	 * 
	 * @param value text in UTF-8
	 * @return calculated hash.
	 */
	public static String hash(String value) {
		MessageDigest digest = HASH.current();
		digest.reset();
		digest.update(value.getBytes(StandardCharsets.UTF_8));
		return StringUtil.byteArray2Hex(digest.digest()).toLowerCase();
	}

	/**
	 * Calculate HMAC:
	 * 
	 * @param key secret key
	 * @param value value in UTF-8 to sign
	 * @return calculated HMAC sign
	 * @throws InvalidKeyException if secret key is inappropriate.
	 */
	public static byte[] hmac(byte[] key, String value) throws InvalidKeyException {
		Mac hmac = MAC.current();
		SecretKey hkey = SecretUtil.create(key, "HMAC");
		hmac.init(hkey);
		Bytes.clear(key);
		byte[] mac = hmac.doFinal(value.getBytes(StandardCharsets.UTF_8));
		SecretUtil.destroy(hkey);
		return mac;
	}

	/**
	 * Encode query.
	 * 
	 * @param query http query
	 * @return encoded http query
	 */
	public static String encodeQuery(String query) {
		StringBuilder result = new StringBuilder();
		if (query != null && !query.isEmpty()) {
			List<Pair> pairs = new ArrayList<>();
			for (String pair : query.split("&")) {
				String name = pair;
				String value = "";
				int index = pair.indexOf("=");
				if (index >= 0) {
					name = pair.substring(0, index);
					if (index < pair.length()) {
						value = pair.substring(index + 1);
					}
				}
				pairs.add(new Pair(name, value));
			}
			pairs.sort(null);
			for (Pair pair : pairs) {
				result.append(urlEncoded(pair.id, false)).append('=');
				result.append(urlEncoded(pair.value, false)).append('&');
			}
			result.setLength(result.length() - 1);
		}
		return result.toString();
	}

	/**
	 * Encode headers.
	 * 
	 * @param headers headers to encode
	 * @param signedHeaders list of signature relevant headers
	 * @return encoded headers
	 */
	public static String encodeHeaders(Headers headers, List<String> signedHeaders) {
		StringBuilder result = new StringBuilder();
		if (signedHeaders.isEmpty()) {
			return "";
		}
		signedHeaders.sort(null);
		for (String header : signedHeaders) {
			result.append(header).append(':');
			List<String> values = headers.get(header);
			if (values != null && !values.isEmpty()) {
				for (String value : values) {
					result.append(value.trim()).append(',');
				}
				result.setLength(result.length() - 1);
			}
			result.append('\n');
		}
		result.append('\n');
		for (String header : signedHeaders) {
			result.append(header).append(';');
		}
		result.setLength(result.length() - 1);
		return result.toString();
	}

	/**
	 * Encode URL.
	 * 
	 * @param url URL to encode
	 * @param keepSlash {@code true} to keep {@code /}, {@code false} to replace
	 *            them.
	 * @return encoded URL.
	 */
	private static String urlEncoded(String url, boolean keepSlash) {
		try {
			final String encoded = URLEncoder.encode(url, StandardCharsets.UTF_8.name());
			final Matcher matcher = AWS_ENCODE_PATTERN.matcher(encoded);
			final StringBuffer buffer = new StringBuffer(encoded.length());

			while (matcher.find()) {
				String replacement = matcher.group(0);
				if (replacement.startsWith("%")) {
					int c = Integer.parseInt(replacement.substring(1), 16);
					if (c != '/' || keepSlash) {
						replacement = new String(new byte[] { (byte) c });
					}
				} else {
					int c = replacement.charAt(0) & 0xff;
					replacement = String.format("%%%02x", c);
				}

				matcher.appendReplacement(buffer, replacement);
			}

			matcher.appendTail(buffer);
			return buffer.toString();
		} catch (final UnsupportedEncodingException e) {
			// This should never happen since we use a built-in constant
			throw new UncheckedIOException(e);
		}
	}

	/**
	 * Format date.
	 * 
	 * @param millis milliseconds of epoch
	 * @return date in ISO ("yyyymmdd").
	 */
	public static String formatDate(long millis) {
		String date = DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(millis).truncatedTo(ChronoUnit.DAYS))
				.substring(0, 10);
		return date.replaceAll("-", "");
	}

	/**
	 * Format date and time
	 * 
	 * @param millis milliseconds of epoch
	 * @return date and time in ISO ("yyyymmddTHHMMssZ").
	 */
	public static String formatDateTime(long millis) {
		String date = DateTimeFormatter.ISO_INSTANT
				.format(Instant.ofEpochMilli(millis).truncatedTo(ChronoUnit.SECONDS));
		return date.replaceAll("[-:]", "");
	}
}
