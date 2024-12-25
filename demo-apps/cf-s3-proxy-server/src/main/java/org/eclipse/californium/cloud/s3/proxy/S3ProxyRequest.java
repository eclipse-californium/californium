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

import java.security.Principal;
import java.util.List;
import java.util.Map;

import org.eclipse.californium.cloud.s3.option.S3ProxyCustomOptions;
import org.eclipse.californium.cloud.s3.resources.S3Devices;
import org.eclipse.californium.cloud.s3.util.DomainDeviceManager;
import org.eclipse.californium.cloud.s3.util.DomainPrincipalInfo;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.MediaTypeRegistry.MediaTypeDefintion;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.option.IntegerOption;
import org.eclipse.californium.core.coap.option.OpaqueOption;
import org.eclipse.californium.core.coap.option.StringOption;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * S3 proxy request.
 * <p>
 * Wrapper for coap requests forwarded to S3.
 * 
 * @since 3.12
 */
public class S3ProxyRequest extends S3PutRequest {

	/**
	 * Name of time in metadata.
	 */
	public static final String METADATA_INTERVAL = "interval";
	/**
	 * Name of coap content type in metadata.
	 */
	public static final String METADATA_COAP_CONTENT_TYPE = "coap-ct";

	/**
	 * CoAP-request.
	 */
	private final Request request;
	/**
	 * Coap-path start index of S3-path.
	 * <p>
	 * Only applied, when provided key was {@code null}.
	 */
	private final int pathStartIndex;
	/**
	 * Coap-path index to insert the device name.
	 * <p>
	 * {@code < 0} to not include the device name.
	 * <p>
	 * Only applied, when provided key was {@code null}.
	 */
	private final int pathPrincipalIndex;
	/**
	 * Additional S3-sub-path.
	 * <p>
	 * Only applied, when provided key was {@code null}.
	 */
	private final String subPath;
	/**
	 * List of coap-etags for GET requests.
	 */
	private final List<OpaqueOption> etags;
	/**
	 * Interval for S3 PUT request.
	 * 
	 * @since 3.13
	 */
	private final Integer interval;
	/**
	 * Coap content-type for S3 PUT request.
	 * 
	 * @since 3.13
	 */
	private final Integer coapContentType;

	/**
	 * Creates S3 proxy request from coap-request.
	 * 
	 * @param request coap-request.
	 * @param key S3 key. If {@code null}, replaced by the coap-path considering
	 *            the pathStartIndex and the pathPrincipalIndex…
	 * @param pathStartIndex coap-path start index. Used when provided key is
	 *            {@code null}.
	 * @param pathPrincipalIndex coap-path index to insert the device name. Used
	 *            when provided key is {@code null}. {@code < 0} to not include
	 *            the device name.
	 * @param subPath sub-path added to coap-path
	 * @param etags coap-etags for GET requests.
	 * @param content content for PUT requests
	 * @param contentType content type for PUT requests
	 * @param timestamp timestamp for PUT requests
	 * @param interval interval for PUT requests
	 * @param coapContentType content-type of coap-request
	 * @param meta map of metadata
	 * @param redirect redirect info, if S3 bucket is temporary redirected after
	 *            creating.
	 * @param cacheMode cache mode.
	 * @since 3.13 interval added
	 */
	public S3ProxyRequest(Request request, String key, int pathStartIndex, int pathPrincipalIndex, String subPath,
			List<OpaqueOption> etags, byte[] content, String contentType, Long timestamp, Integer interval,
			Integer coapContentType, Map<String, String> meta, Redirect redirect, CacheMode cacheMode) {
		super(key, content, contentType, timestamp, meta, redirect, cacheMode);
		if (request == null) {
			throw new NullPointerException("request must not be null!");
		}
		this.request = request;
		this.pathStartIndex = pathStartIndex < 0 ? 0 : pathStartIndex;
		this.pathPrincipalIndex = pathPrincipalIndex;
		this.subPath = subPath;
		this.etags = etags;
		this.interval = interval;
		this.coapContentType = coapContentType;
	}

	/**
	 * Gets the coap-request.
	 * 
	 * @return the coap-request.
	 */
	public Request getCoapRequest() {
		return request;
	}

	/**
	 * Gets the coap-options of the request.
	 * 
	 * @return the coap-options
	 */
	public OptionSet getCoapOptions() {
		return request.getOptions();
	}

	/**
	 * Gets device name.
	 * <p>
	 * Get the device name from the additional info of the principal.
	 * 
	 * @return device name.
	 * 
	 * @see DomainDeviceManager#getPrincipalInfo(Principal)
	 */
	public String getDeviceName() {
		final Principal principal = request.getSourceContext().getPeerIdentity();
		return DomainPrincipalInfo.getName(principal);
	}

	/**
	 * Gets S3 resource key.
	 * <p>
	 * Either the key provided when creating the instance, or, if that was
	 * {@code null}, a key created from the coap-path using the
	 * {@link #pathStartIndex}, the {@link #pathPrincipalIndex} and the
	 * {@link #subPath}.
	 * 
	 * @return S3 resource key
	 */
	@Override
	public String getKey() {
		String key = super.getKey();
		if (key == null) {
			String principal = pathPrincipalIndex >= 0 ? getDeviceName() : "";
			if (principal != null) {
				StringBuilder s3Path = new StringBuilder();
				List<StringOption> coapPath = request.getOptions().getUriPath();
				for (int index = pathStartIndex; index < coapPath.size(); ++index) {
					if (index == pathPrincipalIndex) {
						s3Path.append(principal).append('/');
					}
					s3Path.append(coapPath.get(index).getStringValue()).append('/');
				}
				if (coapPath.size() == pathPrincipalIndex) {
					s3Path.append(principal).append('/');
				}
				if (subPath == null || subPath.isEmpty()) {
					StringUtil.truncateTail(s3Path, "/");
				} else {
					s3Path.append(subPath);
				}
				return s3Path.toString();
			}
		}
		return key;
	}

	/**
	 * Gets canned Access Control List for PUT.
	 * 
	 * @param defaultAcl default ACL
	 * @return canned Access Control List
	 */
	public String getAcl(String defaultAcl) {
		return getAcl(request, defaultAcl);
	}

	/**
	 * Gets coap-etags.
	 * 
	 * @return list of coap-etags
	 */
	public List<OpaqueOption> getETags() {
		return etags;
	}

	/**
	 * Gets coap send interval for S3 PUT.
	 * 
	 * @return interval for S3 PUT.
	 * @since 3.13
	 */
	public Integer getInterval() {
		return interval;
	}

	/**
	 * Gets coap content-type for S3 PUT.
	 * 
	 * @return coap content-type for S3 PUT.
	 * @since 3.13
	 */
	public Integer getCoapContentType() {
		return coapContentType;
	}

	/**
	 * Get metadata for S3 PUT.
	 * 
	 * @return metadata, maybe empty.
	 * @since 3.13
	 */
	@Override
	public Map<String, String> getMetadata() {
		Map<String, String> meta = super.getMetadata();
		if (coapContentType != null) {
			meta.put(METADATA_COAP_CONTENT_TYPE, coapContentType.toString());
		}
		if (interval != null) {
			meta.put(METADATA_INTERVAL, interval.toString());
		}
		return meta;
	}

	/**
	 * Gets canned Access Control List for PUT.
	 * 
	 * @param request coap-request
	 * @param defaultAcl default ACL
	 * @return canned Access Control List
	 */
	public static String getAcl(Request request, String defaultAcl) {
		return request.getOptions().getUriQueryParameter().getArgument(S3Devices.URI_QUERY_OPTION_ACL, defaultAcl);
	}

	/**
	 * Creates S3-proxy-request-builder from coap-request.
	 * 
	 * @param request coap-request.
	 * @return created builder
	 */
	public static Builder builder(Request request) {
		return new Builder(request);
	}

	/**
	 * Creates S3-proxy-request-builder from S3-proxy-request.
	 * 
	 * @param request S3-proxy-request.
	 * @return created builder
	 */
	public static Builder builder(S3ProxyRequest request) {
		return new Builder(request);
	}

	/**
	 * S3-proxy-request-builder.
	 */
	public static class Builder extends S3PutRequest.Builder {

		/**
		 * Coap-request-
		 */
		private final Request request;
		/**
		 * Coap-path start index of S3-path.
		 * <p>
		 * Only applied, when {@link #key} is {@code null}.
		 */
		private int pathStartIndex;
		/**
		 * Coap-path index to insert the device name. {@code < 0} to not include
		 * the device name.
		 * <p>
		 * Only applied, when {@link #key} is {@code null}.
		 */
		private int pathPrincipalIndex = -1;
		/**
		 * Additional S3-sub-path.
		 * <p>
		 * Only applied, when provided {@link #key} was {@code null}.
		 */
		private String subPath;
		/**
		 * List of coap-etags for GET request.
		 */
		private List<OpaqueOption> etags;

		/**
		 * Interval for S3 PUT request.
		 * 
		 * @since 3.13
		 */
		private Integer interval;
		/**
		 * Coap content-type for S3 PUT request.
		 * 
		 * @since 3.13
		 */
		private Integer coapContentType;

		/**
		 * Creates builder from coap-request.
		 * 
		 * @param request coap-request
		 * @throws NullPointerException if request is {@code null}.
		 */
		private Builder(Request request) {
			if (request == null) {
				throw new NullPointerException("request must not be null!");
			}
			this.request = request;
		}

		/**
		 * Creates builder from S3-proxy-request.
		 * 
		 * @param request S3-proxy-request
		 */
		private Builder(S3ProxyRequest request) {
			super(request);
			this.request = request.request;
			this.pathStartIndex = request.pathStartIndex;
			this.pathPrincipalIndex = request.pathPrincipalIndex;
			this.subPath = request.subPath;
			this.etags = request.etags;
		}

		@Override
		public Builder key(String key) {
			super.key(key);
			return this;
		}

		/**
		 * Sets coap-path start index of S3-path.
		 * <p>
		 * Only applied, when {@link #key} is {@code null}.
		 * 
		 * @param pathIndex coap-path start index
		 * @return builder for command chaining
		 */
		public Builder pathStartIndex(int pathIndex) {
			this.pathStartIndex = pathIndex;
			return this;
		}

		/**
		 * Sets coap-path index to insert the device name.
		 * <p>
		 * Only applied, when {@link #key} is {@code null}.
		 * 
		 * @param pathIndex coap-path index to insert the device name
		 * @return builder for command chaining
		 */
		public Builder pathPrincipalIndex(int pathIndex) {
			this.pathPrincipalIndex = pathIndex;
			return this;
		}

		/**
		 * Sets additional sub-path.
		 * <p>
		 * Only applied, when {@link #key} is {@code null}.
		 * 
		 * @param subPath additional sub-path
		 * @return builder for command chaining
		 */
		public Builder subPath(String subPath) {
			this.subPath = subPath;
			return this;
		}

		/**
		 * Sets coap-etags for GET request.
		 * 
		 * @param etags coap-etags
		 * @return builder for command chaining
		 */
		public Builder etags(List<OpaqueOption> etags) {
			this.etags = etags;
			return this;
		}

		/**
		 * Sets coap send interval for S3 PUT request.
		 * 
		 * @param interval coap send interval in s.
		 * @return builder for command chaining
		 * @since 3.13
		 */
		public Builder interval(Integer interval) {
			this.interval = interval;
			return this;
		}

		/**
		 * Sets coap content-type for S3 PUT request.
		 * 
		 * @param coapContentType coap content-type .
		 * @return builder for command chaining
		 * @since 3.13
		 */
		public Builder coapContentType(Integer coapContentType) {
			this.coapContentType = coapContentType;
			return this;
		}

		@Override
		public Builder content(byte[] content) {
			super.content(content);
			return this;
		}

		@Override
		public Builder contentType(String contentType) {
			super.contentType(contentType);
			return this;
		}

		@Override
		public Builder timestamp(Long timestamp) {
			super.timestamp(timestamp);
			return this;
		}

		@Override
		public Builder meta(Map<String, String> meta) {
			super.meta(meta);
			return this;
		}

		@Override
		public Builder redirect(Redirect redirect) {
			super.redirect(redirect);
			return this;
		}

		@Override
		public Builder cacheMode(CacheMode cacheMode) {
			super.cacheMode(cacheMode);
			return this;
		}

		/**
		 * Creates S3-proxy-request.
		 * 
		 * @return S3-proxy-request
		 */
		public S3ProxyRequest build() {
			if (etags == null) {
				etags = request.getOptions().getETags();
			}
			if (content == null) {
				content = request.getPayload();
			}
			if (coapContentType == null) {
				int type = request.getOptions().getContentFormat();
				if (type != MediaTypeRegistry.UNDEFINED) {
					coapContentType = type;
				}
			}
			if (contentType == null && coapContentType != null) {
				MediaTypeDefintion mediaType = MediaTypeRegistry.getDefinition(coapContentType);
				if (mediaType != null) {
					contentType = mediaType.getMime();
				}
			}
			if (interval == null) {
				IntegerOption option = request.getOptions().getOtherOption(S3ProxyCustomOptions.INTERVAL);
				if (option != null) {
					interval = option.getIntegerValue();
				}
			}
			return new S3ProxyRequest(request, key, pathStartIndex, pathPrincipalIndex, subPath, etags, content,
					contentType, timestamp, interval, coapContentType, meta, redirect, cacheMode);
		}
	}
}
