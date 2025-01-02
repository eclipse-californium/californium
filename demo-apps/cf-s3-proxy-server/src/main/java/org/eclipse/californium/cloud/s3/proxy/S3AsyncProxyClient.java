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
package org.eclipse.californium.cloud.s3.proxy;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.FORBIDDEN;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.INTERNAL_SERVER_ERROR;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_FOUND;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.SERVICE_UNAVAILABLE;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.UNAUTHORIZED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.VALID;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoField;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import org.eclipse.californium.cloud.option.TimeOption;
import org.eclipse.californium.cloud.s3.proxy.S3Request.CacheMode;
import org.eclipse.californium.cloud.s3.proxy.S3Request.Redirect;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.option.OpaqueOption;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.LeastRecentlyUpdatedCache;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.core.retry.RetryMode;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3AsyncClientBuilder;
import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;

/**
 * S3 asynchronous proxy client.
 * <p>
 * Implements PUT and GET for device objects and load for other resources.
 * <p>
 * <b>Note:</b> the current implementation uses
 * {@code software.amazon.awssdk:s3:2.27.24} to access S3. That may be replaced
 * in a future version to support different S3 storages for mandates.
 * 
 * @since 3.12
 */
public class S3AsyncProxyClient implements S3ProxyClient {

	private static final Logger LOGGER = LoggerFactory.getLogger(S3AsyncProxyClient.class);

	/**
	 * Default S3 bucket.
	 */
	public static final String DEFAULT_S3_BUCKET = "devices";
	/**
	 * Default concurrency for S3 connections.
	 */
	public static final int DEFAULT_CONCURRENCY = 200;
	/**
	 * Interval to check for redirects. In some cases a new created S3 bucket is
	 * not reachable from the begin and may require to follow a redirect for a
	 * certain time.
	 */
	private static final long REDIRECT_CHECK_INTERVAL = TimeUnit.HOURS.toNanos(1);

	public static final String CONTENT_TYPE_TEXT = "text/plain; charset=utf-8";
	public static final String CONTENT_TYPE_BINARY = "application/octet-stream";

	/**
	 * ETAG cache.
	 */
	private final LeastRecentlyUpdatedCache<String, EtagPair> etags;
	/**
	 * AWS S3 client builder.
	 */
	private S3AsyncClientBuilder builder;
	/**
	 * AWS S3 client.
	 */
	private final S3AsyncClient s3Client;
	/**
	 * Bucket name.
	 */
	private final String bucket;
	/**
	 * Default ACL.
	 */
	private final String acl;
	/**
	 * External https endpoint of S3 bucket.
	 */
	private final String externalEndpoint;
	/**
	 * Region of S3 bucket.
	 */
	private final String region;
	/**
	 * Enable redirect support.
	 */
	private final boolean supportRedirect;
	/**
	 * System nano-seconds to check, if a redirect is still required.
	 */
	private long redirectEnd;
	/**
	 * Redirected external https endpoint of S3 bucket.
	 */
	private String redirectExternalEndpoint;
	/**
	 * Redirect S3 endpoint.
	 */
	private URI redirectEndpoint;
	/**
	 * AWS S3 client for redirected endpoint.
	 */
	private S3AsyncClient redirectS3Client;

	/**
	 * Creates S3 client.
	 * 
	 * @param concurrency number of maximum concurrent requests
	 * @param endpoint S3 endpoint
	 * @param region S3 region
	 * @param bucket S3 bucket
	 * @param acl S3 default ACL (for PUT)
	 * @param externalEndpoint S3 external https endpoint
	 * @param supportRedirect enable redirect support
	 * @param keyId S3 access key ID
	 * @param keySecret S3 access key secret
	 * @param minEtags minimum number of cached ETAGS
	 * @param maxEtags maximum number of cached ETAGS
	 * @param threshold threshold to keep unused ETAGS
	 * @param thresholdUnit time unit of threshold
	 */
	private S3AsyncProxyClient(int concurrency, URI endpoint, String region, String bucket, String acl,
			String externalEndpoint, boolean supportRedirect, String keyId, String keySecret, int minEtags,
			int maxEtags, long threshold, TimeUnit thresholdUnit) {
		builder = S3AsyncClient.builder();
		builder.region(Region.of(region));
		if (endpoint != null) {
			builder.endpointOverride(endpoint);
		}
		if (keyId != null && keySecret != null) {
			AwsBasicCredentials credentials = AwsBasicCredentials.create(keyId, keySecret);
			builder.credentialsProvider(StaticCredentialsProvider.create(credentials));
		}
		builder.overrideConfiguration(
				ClientOverrideConfiguration.builder().retryStrategy(RetryMode.ADAPTIVE_V2).build());
		builder.httpClientBuilder(NettyNioAsyncHttpClient.builder().maxConcurrency(concurrency));
		this.s3Client = builder.build();
		this.bucket = bucket;
		this.acl = acl;
		this.externalEndpoint = externalEndpoint;
		this.region = region;
		this.supportRedirect = supportRedirect;
		this.etags = new LeastRecentlyUpdatedCache<>(minEtags, maxEtags, threshold, thresholdUnit);
	}

	@Override
	public String getExternalEndpoint() {
		synchronized (this) {
			if (redirectExternalEndpoint != null) {
				return redirectExternalEndpoint;
			}
		}
		return externalEndpoint;
	}

	@Override
	public String getRegion() {
		return region;
	}

	@Override
	public String getAcl() {
		return acl;
	}

	/**
	 * Gets effective S3 client considering the redirect information.
	 * 
	 * @param redirect redirect information, or {@code null}, if not used.
	 * @return effective S3 client
	 */
	private S3AsyncClient getClient(Redirect redirect) {
		if (redirect != null) {
			synchronized (this) {
				if (redirectS3Client == null) {
					redirectEndpoint = redirect.endpoint;
					redirectExternalEndpoint = redirect.externalEndpoint;
					redirectS3Client = builder.endpointOverride(redirectEndpoint).build();
					redirectEnd = ClockUtil.nanoRealtime() + REDIRECT_CHECK_INTERVAL;
					return redirectS3Client;
				} else if (redirect.endpoint.equals(redirectEndpoint)) {
					return redirectS3Client;
				} else {
					return null;
				}
			}
		} else {
			long now = ClockUtil.nanoRealtime();
			synchronized (this) {
				S3AsyncClient client = redirectS3Client;
				if (client == null) {
					client = s3Client;
				} else if (now - redirectEnd > 0) {
					client = s3Client;
					redirectEnd = now + REDIRECT_CHECK_INTERVAL;
				}
				return client;
			}
		}
	}

	/**
	 * Reports successful access to S3.
	 * 
	 * @param s3Client successful S3 client.
	 */
	private void success(S3AsyncClient s3Client) {
		if (this.s3Client == s3Client) {
			S3AsyncClient client;
			synchronized (this) {
				redirectEnd = 0;
				redirectEndpoint = null;
				redirectExternalEndpoint = null;
				client = redirectS3Client;
				redirectS3Client = null;
			}
			if (client != null) {
				client.close();
			}
		}
	}

	@Override
	public void put(S3ProxyRequest request, final Consumer<Response> handler) {
		if (request == null) {
			throw new NullPointerException("request must not be null!");
		}
		if (handler == null) {
			throw new NullPointerException("handler must not be null!");
		}
		ResponseCode responseCode = UNAUTHORIZED;
		String responseText = "Authorization missing!";

		final String key = request.getKey();
		if (key != null) {
			final S3AsyncClient s3Client = getClient(request.getRedirect());
			if (s3Client == null) {
				responseCode = INTERNAL_SERVER_ERROR;
				responseText = "Temporary Redirect";
			} else {
				final String redirected = s3Client == this.s3Client ? "" : "(redir.)";
				try {
					PutObjectRequest.Builder putBuilder = PutObjectRequest.builder().bucket(bucket).key(key);
					byte[] content = request.getContent();
					putBuilder.contentLength((long) content.length);
					if (request.getContentType() != null) {
						putBuilder.contentType(request.getContentType());
					}
					if (request.getCacheMode() == CacheMode.NONE) {
						putBuilder.cacheControl("no-store");
					}
					String acl = request.getAcl(this.acl);
					if (acl != null) {
						putBuilder.acl(acl);
					}
					Map<String, String> meta = request.getMetadata();
					if (!meta.isEmpty()) {
						putBuilder.metadata(meta);
					}
					AsyncRequestBody body = AsyncRequestBody.fromBytes(content);
					final long now = ClockUtil.nanoRealtime();
					CompletableFuture<PutObjectResponse> future = s3Client.putObject(putBuilder.build(), body);
					future.whenComplete((putResponse, exception) -> {
						long timeMillis = TimeUnit.NANOSECONDS.toMillis(ClockUtil.nanoRealtime() - now);
						Response response = null;
						if (exception != null) {
							if (s3Client == this.s3Client && request.getRedirect() == null) {
								Redirect redirect = getRedirect(exception);
								if (redirect != null) {
									S3ProxyRequest redirectRequest = S3ProxyRequest.builder(request).redirect(redirect)
											.build();
									LOGGER.info(">Ex./S3-put: {} ({}ms) redirect {}", key, timeMillis, redirect);
									put(redirectRequest, handler);
									return;
								}
							}
							LOGGER.warn(">Ex./S3-put{}: {} ({}ms) {}", redirected, key, timeMillis,
									exception.getMessage());
							response = getCoapResponse(exception, null);
						} else if (putResponse != null) {
							LOGGER.info(">S3-put{}: {} ({}ms) {}", redirected, key, timeMillis, putResponse);
							SdkHttpResponse httpResponse = putResponse.sdkHttpResponse();
							if (httpResponse.isSuccessful()) {
								response = new Response(CHANGED);
								etags.remove(key);
								success(s3Client);
							} else {
								response = getCoapResponse(null, httpResponse);
								LOGGER.info(">S3-put{}: {} ({}ms) {} {}", redirected, key, timeMillis,
										response.getCode(), response.getPayloadString());
							}
						} else {
							LOGGER.warn("S3-put{}: {} ({}ms) no response nor error!", redirected, key, timeMillis);
						}
						if (response == null) {
							response = new Response(INTERNAL_SERVER_ERROR);
						}
						handler.accept(response);
					});
					return;
				} catch (S3Exception e) {
					LOGGER.warn("S3-put{}: {}", redirected, key, e);
					responseCode = INTERNAL_SERVER_ERROR;
					responseText = e.getMessage();
				} catch (SdkException e) {
					LOGGER.warn("S3-put{}: {}", redirected, key, e);
					responseCode = INTERNAL_SERVER_ERROR;
					responseText = e.getMessage();
				}
			}
		}
		Response response = new Response(responseCode);
		response.setPayload(responseText);
		response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		handler.accept(response);
	}

	@Override
	public void save(S3PutRequest request, final Consumer<S3Response> handler) {
		if (request == null) {
			throw new NullPointerException("request must not be null!");
		}
		if (handler == null) {
			throw new NullPointerException("handler must not be null!");
		}
		String responseText = "Authorization missing!";
		S3Response.Builder responseBuilder = S3Response.builder().httpStatusCode(401);

		final String key = request.getKey();
		if (key != null) {
			final S3AsyncClient s3Client = getClient(request.getRedirect());
			if (s3Client == null) {
				responseBuilder.httpStatusCode(500);
				responseText = "Temporary Redirect";
			} else {
				final String redirected = s3Client == this.s3Client ? "" : "(redir.)";
				try {
					PutObjectRequest.Builder putBuilder = PutObjectRequest.builder().bucket(bucket).key(key);
					byte[] content = request.getContent();
					putBuilder.contentLength((long) content.length);
					if (request.getContentType() != null) {
						putBuilder.contentType(request.getContentType());
					}
					if (request.getCacheMode() == CacheMode.NONE) {
						putBuilder.cacheControl("no-store");
					}
					Map<String, String> meta = request.getMetadata();
					if (!meta.isEmpty()) {
						putBuilder.metadata(meta);
					}
					AsyncRequestBody body = AsyncRequestBody.fromBytes(content);
					final long now = ClockUtil.nanoRealtime();
					CompletableFuture<PutObjectResponse> future = s3Client.putObject(putBuilder.build(), body);
					future.whenComplete((putResponse, exception) -> {
						long timeMillis = TimeUnit.NANOSECONDS.toMillis(ClockUtil.nanoRealtime() - now);
						S3Response response = null;
						if (exception != null) {
							if (s3Client == this.s3Client && request.getRedirect() == null) {
								Redirect redirect = getRedirect(exception);
								if (redirect != null) {
									S3PutRequest redirectRequest = S3PutRequest.builder(request).redirect(redirect)
											.build();
									LOGGER.info(">Ex./S3-save: {} ({}ms) redirect {}", key, timeMillis, redirect);
									save(redirectRequest, handler);
									return;
								}
							}
							LOGGER.warn(">Ex./S3-save{}: {} ({}ms) {}", redirected, key, timeMillis,
									exception.getMessage());
							setS3Response(S3Response.builder(), exception, null);
							response = setS3Response(S3Response.builder(), exception, null).build();
						} else if (putResponse != null) {
							LOGGER.info(">S3-save{}: {} ({}ms) {}", redirected, key, timeMillis, putResponse);
							SdkHttpResponse httpResponse = putResponse.sdkHttpResponse();
							if (httpResponse.isSuccessful()) {
								etags.remove(key);
								success(s3Client);
							}
							response = setS3Response(S3Response.builder(), null, httpResponse).build();
						} else {
							LOGGER.warn(">S3-save{}: {} ({}ms) no response nor error!", redirected, key, timeMillis);
						}
						if (response == null) {
							response = S3Response.builder().httpStatusCode(500).build();
						}
						handler.accept(response);
					});
					return;
				} catch (S3Exception e) {
					LOGGER.warn("S3-save{}: {}", redirected, key, e);
					responseBuilder.httpStatusCode(500);
					responseText = e.getMessage();
				} catch (SdkException e) {
					LOGGER.warn("S3-save{}: {}", redirected, key, e);
					responseBuilder.httpStatusCode(500);
					responseText = e.getMessage();
				}
			}
		}
		responseBuilder.contentType(CONTENT_TYPE_TEXT);
		responseBuilder.content(responseText);
		handler.accept(responseBuilder.build());
	}

	@Override
	public void get(S3ProxyRequest request, final Consumer<Response> handler) {
		if (request == null) {
			throw new NullPointerException("request must not be null!");
		}
		if (handler == null) {
			throw new NullPointerException("handler must not be null!");
		}
		ResponseCode responseCode = UNAUTHORIZED;
		String responseText = "Authorization missing!";

		final String key = request.getKey();
		if (key != null) {
			final S3AsyncClient s3Client = getClient(request.getRedirect());
			if (s3Client == null) {
				responseCode = INTERNAL_SERVER_ERROR;
				responseText = "Temporary Redirect";
			} else {
				final String redirected = s3Client == this.s3Client ? "" : "(redir.)";
				try {
					GetObjectRequest.Builder getBuilder = GetObjectRequest.builder().bucket(bucket).key(key);
					if (request.getCacheMode() == CacheMode.CACHE) {
						boolean withEtag = false;
						EtagPair etagPair = etags.update(key);
						if (etagPair != null) {
							List<OpaqueOption> coapETags = request.getETags();
							for (OpaqueOption etag : coapETags) {
								if (etagPair.match(etag.getValue())) {
									getBuilder.ifNoneMatch(etagPair.getS3Etag());
									withEtag = true;
									LOGGER.debug("S3-get: {} with ETAG {}", key, etagPair.getS3Etag());
									break;
								}
							}
						}
						if (!withEtag) {
							LOGGER.debug("S3-get: {} without ETAG", key);
						}
					} else {
						LOGGER.debug("S3-get: {} {}", key, request.getCacheMode());
					}
					final long now = System.nanoTime();
					CompletableFuture<ResponseBytes<GetObjectResponse>> future = s3Client.getObject(getBuilder.build(),
							AsyncResponseTransformer.toBytes());
					future.whenComplete((getResponse, exception) -> {
						long timeMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - now);
						Response response = null;
						if (exception != null) {
							if (s3Client == this.s3Client && request.getRedirect() == null) {
								Redirect redirect = getRedirect(exception);
								if (redirect != null) {
									S3ProxyRequest redirectRequest = S3ProxyRequest.builder(request).redirect(redirect)
											.build();
									LOGGER.info(">Ex./S3-get: {} ({}ms) redirect {}", key, timeMillis, redirect);
									get(redirectRequest, handler);
									return;
								}
							}
							response = getCoapResponse(exception, null);
							if (response != null && response.isSuccess()) {
								if (response.getCode().equals(ResponseCode.VALID)) {
									LOGGER.info(">Ex./S3-get{}: {} ({}ms) no change", redirected, key, timeMillis);
								} else {
									LOGGER.info(">Ex./S3-get{}: {} ({}ms) {}", redirected, key, timeMillis,
											response.getCode());
								}
							} else {
								LOGGER.warn(">Ex./S3-get{}: {} ({}ms) {}", redirected, key, timeMillis,
										exception.getMessage());
							}
						} else if (getResponse != null) {
							GetObjectResponse getObjectResponse = getResponse.response();
							SdkHttpResponse httpResponse = getObjectResponse.sdkHttpResponse();
							if (httpResponse.isSuccessful()) {
								String etag = request.getCacheMode() != CacheMode.NONE ? getObjectResponse.eTag() : "";
								LOGGER.info(">S3-get{}: {} ({}ms) {} {}", redirected, key, timeMillis,
										httpResponse.statusCode(), etag);
								response = new Response(CONTENT);
								response.setPayload(getResponse.asByteArray());
								String contentType = getObjectResponse.contentType();
								if (contentType != null) {
									int[] coapContentTypes = MediaTypeRegistry.parseWithParameter(contentType);
									if (coapContentTypes.length > 0) {
										response.getOptions().setContentFormat(coapContentTypes[0]);
									}
								}
								Long time = getTime(getObjectResponse);
								if (time != null) {
									TimeOption timeOption = TimeOption.DEFINITION.create(time);
									response.getOptions().addOtherOption(timeOption);
								}
								if (!etag.isEmpty()) {
									LOGGER.debug("S3-get: {} add ETAG {}", key, etag);
									EtagPair pair = new EtagPair(etag);
									etags.put(key, pair);
									response.getOptions().addOption(pair.getCoapEtag());
								}
								success(s3Client);
							} else {
								response = getCoapResponse(null, httpResponse);
								LOGGER.info(">S3-get{}: {} ({}ms) {} {}", redirected, key, timeMillis,
										response.getCode(), response.getPayloadString());
							}
						} else {
							LOGGER.warn(">S3-get{}: {} ({}ms) no response nor error!", redirected, key, timeMillis);
						}
						if (response == null) {
							response = new Response(INTERNAL_SERVER_ERROR);
						}
						handler.accept(response);
					});
					return;
				} catch (S3Exception e) {
					LOGGER.warn("S3-get{}: {}", redirected, key, e);
					responseCode = INTERNAL_SERVER_ERROR;
					responseText = e.getMessage();
				} catch (SdkException e) {
					LOGGER.warn("S3-get{}: {}", redirected, key, e);
					responseCode = INTERNAL_SERVER_ERROR;
					responseText = e.getMessage();
				}
			}
		}
		Response response = new Response(responseCode);
		response.setPayload(responseText);
		response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		handler.accept(response);
	}

	@Override
	public void load(S3Request request, final Consumer<S3Response> handler) {
		if (request == null) {
			throw new NullPointerException("request must not be null!");
		}
		if (handler == null) {
			throw new NullPointerException("handler must not be null!");
		}

		final String key = request.getKey();
		if (key != null) {
			final S3AsyncClient s3Client = getClient(request.getRedirect());
			if (s3Client == null) {
				LOGGER.info("S3-load: Temporary Redirect");
			} else {
				final String redirected = s3Client == this.s3Client ? "" : "(redir.)";
				try {
					GetObjectRequest.Builder getBuilder = GetObjectRequest.builder().bucket(bucket).key(key);
					if (request.getCacheMode() == CacheMode.CACHE) {
						EtagPair etagPair = etags.update(key);
						if (etagPair != null) {
							getBuilder.ifNoneMatch(etagPair.getS3Etag());
							LOGGER.debug("S3-load: {} with ETAG {}", key, etagPair.getS3Etag());
						} else {
							LOGGER.debug("S3-load: {} without ETAG", key);
						}
					} else {
						LOGGER.debug("S3-load: {} {}", key, request.getCacheMode());
					}

					final long now = System.nanoTime();
					CompletableFuture<ResponseBytes<GetObjectResponse>> future = s3Client.getObject(getBuilder.build(),
							AsyncResponseTransformer.toBytes());
					future.whenComplete((getResponse, exception) -> {
						long timeMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - now);
						S3Response response = null;
						if (exception != null) {
							if (s3Client == this.s3Client && request.getRedirect() == null) {
								Redirect redirect = getRedirect(exception);
								if (redirect != null) {
									S3Request redirectRequest = S3Request.builder(request).redirect(redirect).build();
									LOGGER.info(">Ex./S3-load: {} ({}ms) redirect {}", key, timeMillis, redirect);
									load(redirectRequest, handler);
									return;
								}
							}
							response = setS3Response(S3Response.builder(), exception, null).build();
							if (response.getHttpStatusCode() == 304) {
								LOGGER.debug(">Ex./S3-load{}: {} ({}ms) no change", redirected, key, timeMillis);
							} else if (response.getHttpStatusCode() < 300) {
								LOGGER.info(">Ex./S3-load{}: {} ({}ms) {}", redirected, key, timeMillis,
										response.getHttpStatusCode());
							} else {
								LOGGER.warn(">Ex./S3-load{}: {} ({}ms) {}", redirected, key, timeMillis,
										exception.getMessage());
							}
						} else if (getResponse != null) {
							GetObjectResponse getObjectResponse = getResponse.response();
							SdkHttpResponse httpResponse = getObjectResponse.sdkHttpResponse();
							if (httpResponse.isSuccessful()) {
								String etag = request.getCacheMode() != CacheMode.NONE ? getObjectResponse.eTag() : "";
								if (LOGGER.isDebugEnabled()) {
									LOGGER.debug(">S3-load{}: {} ({}ms) {} {}", redirected, key, timeMillis,
											httpResponse.statusCode(), etag);
								} else {
									LOGGER.info(">S3-load{}: {} ({}ms) {}", redirected, key, timeMillis,
											httpResponse.statusCode());
								}
								if (!etag.isEmpty()) {
									LOGGER.debug("S3-load: {} add ETAG {}", key, etag);
									EtagPair pair = new EtagPair(etag);
									etags.put(key, pair);
								}
								S3Response.Builder builder = S3Response.builder();
								builder.httpStatusCode(httpResponse.statusCode());
								builder.contentType(getObjectResponse.contentType());
								builder.contentLength(getObjectResponse.contentLength());
								builder.content(getResponse.asInputStream());
								builder.timestamp(getObjectResponse.lastModified().getEpochSecond());
								builder.meta(getObjectResponse.metadata());
								response = builder.build();
								success(s3Client);
							} else if (httpResponse.statusCode() == 304) {
								LOGGER.info(">S3-load{}: {} ({}ms) no change", redirected, key, timeMillis);
								S3Response.Builder builder = S3Response.builder();
								builder.httpStatusCode(httpResponse.statusCode());
								response = builder.build();
								success(s3Client);
							} else {
								response = setS3Response(S3Response.builder(), null, httpResponse).build();
								LOGGER.warn(">S3-load{}: {} ({}ms) {} {}", redirected, key, timeMillis,
										response.getHttpStatusCode(), response.getContent());
							}
						} else {
							LOGGER.warn(">S3-load{}: {} ({}ms) no response nor error!", redirected, key, timeMillis);
						}
						if (response == null) {
							response = S3Response.builder().httpStatusCode(500).build();
						}
						handler.accept(response);
					});
					return;
				} catch (S3Exception e) {
					LOGGER.warn("S3-load{}: {}", redirected, key, e);
				} catch (SdkException e) {
					LOGGER.warn("S3-load{}: {}", redirected, key, e);
				}
			}
		}
		LOGGER.info("S3-load: key missing!");
		handler.accept(null);
	}

	@Override
	public void list(S3ListRequest request, final Consumer<S3ListResponse> handler) {
		if (request == null) {
			throw new NullPointerException("request must not be null!");
		}
		if (handler == null) {
			throw new NullPointerException("handler must not be null!");
		}
		final String key = request.getKey();
		if (key != null) {
			final S3AsyncClient s3Client = getClient(request.getRedirect());
			if (s3Client == null) {
				LOGGER.info("S3-list: Temporary Redirect");
			} else {
				final String redirected = s3Client == this.s3Client ? "" : "(redir.)";
				try {
					ListObjectsV2Request.Builder listBuilder = ListObjectsV2Request.builder().bucket(bucket)
							.prefix(key);
					if (request.getDelimiter() != null) {
						listBuilder.delimiter(request.getDelimiter());
					}
					if (request.getStartAfter() != null) {
						listBuilder.startAfter(request.getStartAfter());
					}
					if (request.getMaximumKeys() != null) {
						listBuilder.maxKeys(request.getMaximumKeys());
					}
					LOGGER.debug("S3-list: {}", key);

					final long now = System.nanoTime();
					CompletableFuture<ListObjectsV2Response> future = s3Client.listObjectsV2(listBuilder.build());
					future.whenComplete((listResponse, exception) -> {
						long timeMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - now);
						S3ListResponse response = null;
						if (exception != null) {
							if (s3Client == this.s3Client && request.getRedirect() == null) {
								Redirect redirect = getRedirect(exception);
								if (redirect != null) {
									S3ListRequest redirectRequest = S3ListRequest.builder(request).redirect(redirect)
											.build();
									LOGGER.info(">Ex./S3-list: {} ({}ms) redirect {}", key, timeMillis, redirect);
									list(redirectRequest, handler);
									return;
								}
							}
							response = setS3Response(S3ListResponse.builder(), exception, null).build();
							if (response.getHttpStatusCode() == 304) {
								LOGGER.debug(">Ex./S3-list{}: {} ({}ms) no change", redirected, key, timeMillis);
							} else if (response.getHttpStatusCode() < 300) {
								LOGGER.info(">Ex./S3-list{}: {} ({}ms) {}", redirected, key, timeMillis,
										response.getHttpStatusCode());
							} else {
								LOGGER.warn(">Ex./S3-list{}: {} ({}ms) {}", redirected, key, timeMillis,
										exception.getMessage());
							}
						} else if (listResponse != null) {
							LOGGER.info(">S3-list{}: {} ({}ms)", redirected, key, timeMillis);

							S3ListResponse.Builder builder = S3ListResponse.builder();
							List<String> prefixes = new ArrayList<>();
							List<CommonPrefix> commonPrefixes = listResponse.commonPrefixes();
							for (CommonPrefix prefix : commonPrefixes) {
								LOGGER.trace(">S3-list{}-prefix: {}", redirected, prefix.prefix());
								prefixes.add(prefix.prefix());
							}
							builder.prefixes(prefixes);

							List<S3ListResponse.S3Object> objects = new ArrayList<>();
							List<S3Object> list = listResponse.contents();
							for (S3Object s3Object : list) {
								LOGGER.trace(">S3-list{}: {}", redirected, s3Object.key());
								objects.add(new S3ListResponse.S3Object(s3Object.key(), s3Object.eTag()));
							}
							builder.objects(objects);

							response = builder.build();
							success(s3Client);
						} else {
							LOGGER.warn(">S3-list{}: {} ({}ms) no response nor error!", redirected, key, timeMillis);
						}
						if (response == null) {
							response = S3ListResponse.builder().httpStatusCode(500).build();
						}
						handler.accept(response);
					});
					return;
				} catch (S3Exception e) {
					LOGGER.warn("S3-list{}: {}", redirected, key, e);
				} catch (SdkException e) {
					LOGGER.warn("S3-list{}: {}", redirected, key, e);
				}
			}
		}
		LOGGER.info("S3-list: key missing!");
		handler.accept(null);
	}

	@Override
	public void delete(S3Request request, final Consumer<S3Response> handler) {
		if (request == null) {
			throw new NullPointerException("request must not be null!");
		}
		if (handler == null) {
			throw new NullPointerException("handler must not be null!");
		}
		final String key = request.getKey();
		if (key != null) {
			final S3AsyncClient s3Client = getClient(request.getRedirect());
			if (s3Client == null) {
				LOGGER.info("S3-delete: Temporary Redirect");
			} else {
				final String redirected = s3Client == this.s3Client ? "" : "(redir.)";
				try {
					DeleteObjectRequest.Builder deleteBuilder = DeleteObjectRequest.builder().bucket(bucket).key(key);
					LOGGER.debug("S3-list: {}", key);

					final long now = System.nanoTime();
					CompletableFuture<DeleteObjectResponse> future = s3Client.deleteObject(deleteBuilder.build());
					future.whenComplete((delResponse, exception) -> {
						long timeMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - now);
						S3Response response = null;
						if (exception != null) {
							if (s3Client == this.s3Client && request.getRedirect() == null) {
								Redirect redirect = getRedirect(exception);
								if (redirect != null) {
									S3Request redirectRequest = S3Request.builder(request).redirect(redirect).build();
									LOGGER.info(">Ex./S3-delete: {} ({}ms) redirect {}", key, timeMillis, redirect);
									delete(redirectRequest, handler);
									return;
								}
							}
							response = setS3Response(S3Response.builder(), exception, null).build();
							if (response.getHttpStatusCode() == 304) {
								LOGGER.debug(">Ex./S3-delete{}: {} ({}ms) no change", redirected, key, timeMillis);
							} else if (response.getHttpStatusCode() < 300) {
								LOGGER.info(">Ex./S3-delete{}: {} ({}ms) {}", redirected, key, timeMillis,
										response.getHttpStatusCode());
							} else {
								LOGGER.warn(">Ex./S3-delete{}: {} ({}ms) {}", redirected, key, timeMillis,
										exception.getMessage());
							}
						} else if (delResponse != null) {
							LOGGER.info(">S3-delete{}: {} ({}ms)", redirected, key, timeMillis);
							S3Response.Builder builder = S3Response.builder();
							builder.httpStatusCode(204);
							response = builder.build();
							success(s3Client);
						} else {
							LOGGER.warn(">S3-delete{}: {} ({}ms) no response nor error!", redirected, key, timeMillis);
						}
						if (response == null) {
							response = S3Response.builder().httpStatusCode(500).build();
						}
						handler.accept(response);
					});
					return;
				} catch (S3Exception e) {
					LOGGER.warn("S3-delete{}: {}", redirected, key, e);
				} catch (SdkException e) {
					LOGGER.warn("S3-delete{}: {}", redirected, key, e);
				}
			}
		}
		LOGGER.info("S3-delete: key missing!");
		handler.accept(null);
	}

	/**
	 * Gets redirect information from exception.
	 * 
	 * @param exception exception while executing S3 request.
	 * @return redirect information, or {@code null}, if not available or not
	 *         enabled.
	 * @see #supportRedirect
	 */
	public Redirect getRedirect(Throwable exception) {
		if (supportRedirect) {
			Throwable cause = exception;
			if (exception instanceof CompletionException) {
				cause = exception.getCause();
			}
			if (cause instanceof S3Exception) {
				AwsErrorDetails details = ((S3Exception) cause).awsErrorDetails();
				SdkHttpResponse httpResponse = details.sdkHttpResponse();
				String location = httpResponse.firstMatchingHeader("Location").orElse(null);
				if (location != null && httpResponse.statusCode() == 307) {
					try {
						URI uri = new URI(location);
						String endpoint = StringUtil.truncateHeader(uri.getHost(), bucket + ".");
						URI base = new URI(uri.getScheme(), null, endpoint, uri.getPort(), null, null, null);
						URI externalEndpoint = new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), null, null,
								null);
						return new Redirect(base, externalEndpoint.toASCIIString());
					} catch (URISyntaxException e) {
					}
				}
			}
		}
		return null;
	}

	/**
	 * Gets coap response.
	 * 
	 * @param exception exception while executing S3 request.
	 * @param httpErrorResponse http error response for S3 request.
	 * @return coap response
	 */
	public Response getCoapResponse(Throwable exception, SdkHttpResponse httpErrorResponse) {
		Response response = null;
		if (httpErrorResponse == null) {
			Throwable cause = exception;
			if (exception instanceof CompletionException) {
				cause = exception.getCause();
			}
			if (cause instanceof S3Exception) {
				AwsErrorDetails details = ((S3Exception) cause).awsErrorDetails();
				httpErrorResponse = details.sdkHttpResponse();
			}
			if (httpErrorResponse == null) {
				response = new Response(INTERNAL_SERVER_ERROR);
				response.setPayload(exception.getMessage());
				response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				return response;
			}
		}
		if (LOGGER.isTraceEnabled()) {
			Map<String, List<String>> headers = httpErrorResponse.headers();
			List<String> headerNames = new ArrayList<>(headers.keySet());
			headerNames.sort(null);
			for (String name : headerNames) {
				LOGGER.trace("   {}: {}", name, headers.get(name));
			}
		}
		if (httpErrorResponse.statusCode() == 503) {
			response = new Response(SERVICE_UNAVAILABLE);
			response.getOptions().setMaxAge(10);
			response.setPayload(httpErrorResponse.statusText().orElse(""));
			response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		} else if (httpErrorResponse.statusCode() == 404) {
			response = new Response(NOT_FOUND);
			response.setPayload(httpErrorResponse.statusText().orElse(""));
			response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		} else if (httpErrorResponse.statusCode() == 403) {
			response = new Response(FORBIDDEN);
			response.setPayload(httpErrorResponse.statusText().orElse(""));
			response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		} else if (httpErrorResponse.statusCode() == 304) {
			response = new Response(VALID);
		} else if (httpErrorResponse.statusCode() == 307) {
			response = new Response(INTERNAL_SERVER_ERROR);
			response.setPayload("Temporary redirect " + httpErrorResponse.firstMatchingHeader("Location").orElse(""));
			response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		} else {
			response = new Response(INTERNAL_SERVER_ERROR);
			StringBuilder text = new StringBuilder();
			text.append(httpErrorResponse.statusCode()).append(": ");
			text.append(httpErrorResponse.statusText().orElse(""));
			String location = httpErrorResponse.firstMatchingHeader("Location").orElse(null);
			if (location != null) {
				text.append(" => ").append(location);
			}
			response.setPayload(text.toString());
			response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		}
		return response;
	}

	/**
	 * Sets S3 response.
	 * 
	 * @param <B> S3 response builder type.
	 * @param builder S3 response builder to set response to.
	 * @param exception exception while executing S3 request.
	 * @param httpErrorResponse http error response for S3 request.
	 * @return S3 response builder for queuing.
	 */
	public <B extends S3Response.Builder> B setS3Response(B builder, Throwable exception,
			SdkHttpResponse httpErrorResponse) {
		if (httpErrorResponse == null) {
			Throwable cause = exception;
			if (exception instanceof CompletionException) {
				cause = exception.getCause();
			}
			if (cause instanceof S3Exception) {
				AwsErrorDetails details = ((S3Exception) cause).awsErrorDetails();
				httpErrorResponse = details.sdkHttpResponse();
			}
			if (httpErrorResponse == null) {
				builder.httpStatusCode(500);
				builder.content(exception.getMessage());
				builder.contentType(CONTENT_TYPE_TEXT);
				return builder;
			}
		}
		if (LOGGER.isTraceEnabled()) {
			Map<String, List<String>> headers = httpErrorResponse.headers();
			List<String> headerNames = new ArrayList<>(headers.keySet());
			headerNames.sort(null);
			for (String name : headerNames) {
				LOGGER.trace("   {}: {}", name, headers.get(name));
			}
		}
		builder.httpStatusCode(httpErrorResponse.statusCode());
		builder.contentType(CONTENT_TYPE_TEXT);
		StringBuilder text = new StringBuilder();
		text.append(httpErrorResponse.statusText().orElse(""));
		String location = httpErrorResponse.firstMatchingHeader("Location").orElse(null);
		if (location != null) {
			text.append(" => ").append(location);
		}
		builder.content(text.toString());
		return builder;
	}

	/**
	 * Gets meta-data time from S3 response.
	 * 
	 * @param getObjectResponse S3 response of GET request.
	 * @return time in milliseconds since 1.1.1970
	 */
	public Long getTime(GetObjectResponse getObjectResponse) {
		if (getObjectResponse.hasMetadata()) {
			String timestamp = getObjectResponse.metadata().get(S3PutRequest.METADATA_TIME);
			if (timestamp != null) {
				try {
					return Long.parseLong(timestamp);
				} catch (NumberFormatException ex) {
					try {
						Instant time = DateTimeFormatter.ISO_INSTANT.parse(timestamp, Instant::from);
						return time.getLong(ChronoField.MILLI_OF_SECOND);
					} catch (DateTimeParseException ex2) {
					}
				}
			}
		}
		return null;
	}

	/**
	 * Pair of S3 and CoAP ETAGs.
	 */
	public static class EtagPair {

		/**
		 * CoAP ETAG.
		 */
		private final OpaqueOption coapEtag;
		/**
		 * S3 ETAG.
		 */
		private final String s3Etag;

		/**
		 * Creates ETAG pair.
		 * 
		 * @param s3Etag S3 ETAG.
		 */
		private EtagPair(String s3Etag) {
			this.s3Etag = s3Etag;
			byte[] etag = s3Etag.getBytes(StandardCharsets.UTF_8);
			byte[] data = new byte[6];
			int destIndex = 0;
			int shift = 0;
			for (int srcIndex = 0; srcIndex < etag.length; ++srcIndex) {
				data[destIndex] += (etag[srcIndex] << shift);
				++destIndex;
				if (destIndex >= data.length) {
					destIndex = 0;
					++shift;
				}
			}
			this.coapEtag = StandardOptionRegistry.ETAG.create(data);
		}

		/**
		 * Gets S3 ETAG.
		 * 
		 * @return S3 ETAG
		 */
		public String getS3Etag() {
			return s3Etag;
		}

		/**
		 * Gets coap ETAG.
		 * 
		 * @return coap ETAg
		 */
		public OpaqueOption getCoapEtag() {
			return coapEtag;
		}

		/**
		 * Checks, if etag is matching the coap etag.
		 * 
		 * @param etag coap etag
		 * @return {@code true}, if coap etags are matching, {@code false},
		 *         otherwise.
		 */
		public boolean match(byte[] etag) {
			return Arrays.equals(coapEtag.getValue(), etag);
		}
	}

	/**
	 * Consumer with no operation.
	 */
	public final static Consumer<Response> NOP = new Consumer<Response>() {

		@Override
		public void accept(Response response) {
			// blank by intention
		}
	};

	/**
	 * Creates builder for S3 client.
	 * 
	 * @return builder for S3 client
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Builder for S3 client.
	 */
	public static class Builder {

		/**
		 * S3 endpoint.
		 */
		private URI endpoint;
		/**
		 * S3 external https endpoint.
		 */
		private String externalEndpoint;
		/**
		 * S3 region.
		 */
		private String region = S3ProxyClient.DEFAULT_REGION;
		/**
		 * S3 bucket.
		 */
		private String bucket = DEFAULT_S3_BUCKET;
		/**
		 * S3 default ACL.
		 */
		private String acl;
		/**
		 * S3 access key ID.
		 */
		private String keyId;
		/**
		 * S3 access key secret.
		 */
		private String keySecret;
		/**
		 * Support S3 redirect.
		 */
		private boolean supportRedirect;
		/**
		 * Maximum number of concurrent S3 request.
		 */
		private int concurrency = DEFAULT_CONCURRENCY;
		/**
		 * Minimum number of cached ETAGs.
		 */
		private int minEtags = 100;
		/**
		 * Maximum number of cached ETAGs.
		 */
		private int maxEtags = 1000;
		/**
		 * Threshold to keep unused ETAGS.
		 */
		private long threshold = 24;
		/**
		 * Time unit of the {@link #threshold}.
		 */
		private TimeUnit thresholdUnit = TimeUnit.HOURS;

		/**
		 * Sets S3 endpoint from URI.
		 * 
		 * @param endpoint S3 endpoint
		 * @return builder for command chaining
		 */
		public Builder endpoint(URI endpoint) {
			this.endpoint = endpoint;
			return this;
		}

		/**
		 * Sets S3 endpoint from text.
		 * 
		 * @param endpoint S3 endpoint
		 * @return builder for command chaining
		 */
		public Builder endpoint(String endpoint) {
			this.endpoint = URI.create(endpoint);
			return this;
		}

		/**
		 * Sets S3 external https endpoint.
		 * 
		 * @param externalEndpoint S3 external https endpoint
		 * @return builder for command chaining
		 */
		public Builder externalEndpoint(String externalEndpoint) {
			this.externalEndpoint = externalEndpoint;
			return this;
		}

		/**
		 * Sets S3 region.
		 * 
		 * @param region S3 region. If {@code null},
		 *            {@link S3ProxyClient#DEFAULT_REGION} is set.
		 * @return builder for command chaining
		 */
		public Builder region(String region) {
			if (region == null) {
				this.region = S3ProxyClient.DEFAULT_REGION;
			} else {
				this.region = region;
			}
			return this;
		}

		/**
		 * Sets S3 bucket.
		 * 
		 * @param bucket S3 bucket. If {@code null},
		 *            {@link S3AsyncProxyClient#DEFAULT_S3_BUCKET} is set.
		 * @return builder for command chaining
		 */
		public Builder bucket(String bucket) {
			if (bucket == null) {
				this.bucket = DEFAULT_S3_BUCKET;
			} else {
				this.bucket = bucket;
			}
			return this;
		}

		/**
		 * Sets S3 default ACL.
		 * 
		 * @param acl S3 default ACL.
		 * @return builder for command chaining
		 */
		public Builder acl(String acl) {
			this.acl = acl;
			return this;
		}

		/**
		 * Set S3 access key ID.
		 * 
		 * @param keyId S3 access key ID.
		 * @return builder for command chaining
		 */
		public Builder keyId(String keyId) {
			this.keyId = keyId;
			return this;
		}

		/**
		 * Sets S3 access key secret.
		 * 
		 * @param keySecret S3 access key secret.
		 * @return builder for command chaining
		 */
		public Builder keySecret(String keySecret) {
			this.keySecret = keySecret;
			return this;
		}

		/**
		 * Sets maximum number of concurrent requests.
		 * 
		 * @param concurrency maximum number of concurrent requests
		 * @return builder for command chaining
		 */
		public Builder concurrency(int concurrency) {
			this.concurrency = concurrency;
			return this;
		}

		/**
		 * Enables redirect support for S3.
		 * 
		 * @param enable {@code true} to enable redirect support, {@code false},
		 *            if not.
		 * @return builder for command chaining
		 */
		public Builder supportRedirect(boolean enable) {
			this.supportRedirect = enable;
			return this;
		}

		/**
		 * Sets minimum number of cached ETAGs.
		 * 
		 * @param min minimum number of cached ETAGs
		 * @return builder for command chaining
		 */
		public Builder minEtags(int min) {
			this.minEtags = min;
			return this;
		}

		/**
		 * Sets maximum number of cached ETAGs.
		 * 
		 * @param max maximum number of cached ETAGs
		 * @return builder for command chaining
		 */
		public Builder maxEtags(int max) {
			this.maxEtags = max;
			return this;
		}

		/**
		 * Sets threshold for unused cached ETAGs.
		 * 
		 * @param threshold threshold
		 * @param unit time unit of threshold
		 * @return builder for command chaining
		 */
		public Builder threshold(long threshold, TimeUnit unit) {
			this.threshold = threshold;
			this.thresholdUnit = unit;
			return this;
		}

		/**
		 * Creates S3 client.
		 * 
		 * @return created S3 client
		 */
		public S3AsyncProxyClient build() {
			return new S3AsyncProxyClient(concurrency, endpoint, region, bucket, acl, externalEndpoint, supportRedirect,
					keyId, keySecret, minEtags, maxEtags, threshold, thresholdUnit);
		}
	}
}
