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
import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.cloud.s3.resources.S3Devices;
import org.eclipse.californium.cloud.s3.util.DomainDeviceManager;
import org.eclipse.californium.cloud.s3.util.DomainDeviceManager.DomainDeviceInfo;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.MediaTypeRegistry.MediaTypeDefintion;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * S3 proxy request.
 * 
 * Wrapper for coap requests forwarded to S3.
 * 
 * @since 3.12
 */
public class S3ProxyRequest extends S3Request {

	/**
	 * CoAP-request.
	 */
	private final Request request;
	/**
	 * Coap-path start index of S3-path.
	 * 
	 * Only applied, when provided key was {@code null}.
	 */
	private final int pathStartIndex;
	/**
	 * Coap-path index to insert the device name. {@code < 0} to not include the
	 * device name.
	 * 
	 * Only applied, when provided key was {@code null}.
	 */
	private final int pathPrincipalIndex;
	/**
	 * Additional S3-sub-path.
	 * 
	 * Only applied, when provided key was {@code null}.
	 */
	private final String subPath;
	/**
	 * List of coap-etags for GET requests.
	 */
	private final List<Option> etags;
	/**
	 * Content for POST requests.
	 */
	private final byte[] content;
	/**
	 * Content type for POST requests.
	 */
	private final String contentType;
	/**
	 * Timestamp for POST request.
	 */
	private final Long timestamp;

	/**
	 * Create S3 proxy request from coap-request.
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
	 * @param redirect redirect info, if S3 bucket is temporary redirected after
	 *            creating.
	 */
	public S3ProxyRequest(Request request, String key, int pathStartIndex, int pathPrincipalIndex, String subPath,
			List<Option> etags, byte[] content, String contentType, Long timestamp, Redirect redirect) {
		super(key, redirect);
		if (request == null) {
			throw new NullPointerException("request must not be null!");
		}
		this.request = request;
		this.pathStartIndex = pathStartIndex < 0 ? 0 : pathStartIndex;
		this.pathPrincipalIndex = pathPrincipalIndex;
		this.subPath = subPath;
		this.etags = etags;
		this.content = content;
		this.contentType = contentType;
		this.timestamp = timestamp;
	}

	/**
	 * Get the coap-request.
	 * 
	 * @return the coap-request.
	 */
	public Request getCoapRequest() {
		return request;
	}

	/**
	 * Get the coap-options of the request.
	 * 
	 * @return the coap-options
	 */
	public OptionSet getCoapOptions() {
		return request.getOptions();
	}

	/**
	 * Get device name.
	 * 
	 * Get the device name from the additional info of the principal.
	 * 
	 * @return device name.
	 * 
	 * @see DomainDeviceManager#getDeviceInfo(Principal)
	 */
	public String getDeviceName() {
		final Principal principal = request.getSourceContext().getPeerIdentity();
		final DomainDeviceInfo info = DomainDeviceManager.getDeviceInfo(principal);
		return info != null ? info.name : null;
	}

	/**
	 * Get S3 resource key.
	 * 
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
				List<String> coapPath = request.getOptions().getUriPath();
				for (int index = pathStartIndex; index < coapPath.size(); ++index) {
					if (index == pathPrincipalIndex) {
						s3Path.append(principal).append('/');
					}
					s3Path.append(coapPath.get(index)).append('/');
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
	 * Get canned Access Control List for PUT.
	 * 
	 * @param defaultAcl default ACL
	 * @return canned Access Control List
	 */
	public String getAcl(String defaultAcl) {
		return getAcl(request, defaultAcl);
	}

	/**
	 * Get coap-etags.
	 * 
	 * @return list of coap-etags
	 */
	public List<Option> getETags() {
		return etags;
	}

	/**
	 * Get content for PUT.
	 * 
	 * @return content for PUT.
	 */
	public byte[] getContent() {
		return content;
	}

	/**
	 * Get content type for PUT.
	 * 
	 * @return content type for PUT.
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * Get timestamp for PUT.
	 * 
	 * @return timestamp for PUT.
	 */
	public Long getTimestamp() {
		return timestamp;
	}

	/**
	 * Get canned Access Control List for PUT.
	 * 
	 * @param request coap-request
	 * @param defaultAcl default ACL
	 * @return canned Access Control List
	 */
	public static String getAcl(Request request, String defaultAcl) {
		return request.getOptions().getUriQueryParameter().getArgument(S3Devices.URI_QUERY_OPTION_ACL, defaultAcl);
	}

	/**
	 * Get content type from coap-message.
	 * 
	 * @param message coap-message
	 * @return content type.
	 * @see MediaTypeRegistry
	 */
	public static String getContentType(Message message) {
		int format = message.getOptions().getContentFormat();
		MediaTypeDefintion mediaType = MediaTypeRegistry.getDefinition(format);
		return mediaType != null ? mediaType.getMime() : null;
	}

	/**
	 * Create S3-proxy-request-builder from coap-request.
	 * 
	 * @param request coap-request.
	 * @return created builder
	 */
	public static Builder builder(Request request) {
		return new Builder(request);
	}

	/**
	 * Create S3-proxy-request-builder from S3-proxy-request.
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
	public static class Builder extends S3Request.Builder {

		/**
		 * Coap-request-
		 */
		private final Request request;
		/**
		 * Coap-path start index of S3-path.
		 * 
		 * Only applied, when {@link #key} is {@code null}.
		 */
		private int pathStartIndex;
		/**
		 * Coap-path index to insert the device name. {@code < 0} to not include
		 * the device name.
		 * 
		 * Only applied, when {@link #key} is {@code null}.
		 */
		private int pathPrincipalIndex = -1;
		/**
		 * Additional S3-sub-path.
		 * 
		 * Only applied, when provided {@link #key} was {@code null}.
		 */
		private String subPath;
		/**
		 * List of coap-etags for GET request.
		 */
		private List<Option> etags;
		/**
		 * Content for PUT request.
		 */
		private byte[] content;
		/**
		 * Content-type for PUT request.
		 */
		private String contentType;
		/**
		 * Timestamp for PUT request.
		 */
		private Long timestamp;

		/**
		 * Create builder from coap-request.
		 * 
		 * @param request coap-request
		 */
		private Builder(Request request) {
			this.request = request;
		}

		/**
		 * Create builder from S3-proxy-request.
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
			this.content = request.content;
			this.contentType = request.contentType;
			this.timestamp = request.timestamp;
		}

		@Override
		public Builder key(String key) {
			super.key(key);
			return this;
		}

		/**
		 * Set coap-path start index of S3-path.
		 * 
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
		 * Set coap-path index to insert the device name.
		 * 
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
		 * Set additional sub-path.
		 * 
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
		 * Set coap-etags for GET request.
		 * 
		 * @param etags coap-etags
		 * @return builder for command chaining
		 */
		public Builder etags(List<Option> etags) {
			this.etags = etags;
			return this;
		}

		/**
		 * Set content for PUT request.
		 * 
		 * @param content content
		 * @return builder for command chaining
		 */
		public Builder content(byte[] content) {
			this.content = content;
			return this;
		}

		/**
		 * Set content-type for PUT request.
		 * 
		 * @param contentType content-type for PUT request
		 * @return builder for command chaining
		 */
		public Builder contentType(String contentType) {
			this.contentType = contentType;
			return this;
		}

		/**
		 * Set timestamp for PUT request.
		 * 
		 * @param timestamp timestamp
		 * @return builder for command chaining
		 */
		public Builder timestamp(Long timestamp) {
			this.timestamp = timestamp;
			return this;
		}

		@Override
		public Builder redirect(Redirect redirect) {
			super.redirect(redirect);
			return this;
		}

		/**
		 * Creates S3-proxy-request.
		 * 
		 * @return S3-proxy-request
		 */
		public S3ProxyRequest build() {
			if (etags == null) {
				List<byte[]> coapEtags = request.getOptions().getETags();
				etags = new ArrayList<>(coapEtags.size());
				for (byte[] etag : coapEtags) {
					etags.add(StandardOptionRegistry.ETAG.create(etag));
				}
			}
			if (content == null) {
				content = request.getPayload();
			}
			if (contentType == null) {
				contentType = getContentType(request);
			}
			return new S3ProxyRequest(request, key, pathStartIndex, pathPrincipalIndex, subPath, etags, content,
					contentType, timestamp, redirect);
		}
	}
}
