/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.config;

import java.net.InetSocketAddress;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.util.SecretUtil;

/**
 * DTLS cluster connector configuration.
 * 
 * @since 2.5
 */
public final class DtlsClusterConnectorConfig {

	/**
	 * Local socket address for cluster internal connector.
	 */
	private InetSocketAddress address;
	/**
	 * PSK identity for cluster internal connector. Maybe {@code null}, if
	 * encryption is not used.
	 */
	private String identity;
	/**
	 * PSK secret for cluster internal connector. Maybe {@code null}, if
	 * encryption is not used.
	 */
	private SecretKey secret;
	/**
	 * Enable to use a MAC for forwarded and backwarded messages.
	 * 
	 * Only possible, if encryption is used.
	 */
	private Boolean clusterMac;
	/**
	 * Enable backward messages.
	 * 
	 * Send outgoing messages back via original receiving connector (router).
	 */
	private Boolean backwardMessages;

	/**
	 * Get local socket address for internal cluster connector.
	 * 
	 * @return local socket address for internal cluster connector
	 */
	public InetSocketAddress getAddress() {
		return address;
	}

	/**
	 * Gets PSK identity for cluster internal connector.
	 * 
	 * @return PSK identity for cluster internal connector. Maybe {@code null},
	 *         if encryption is not used.
	 */
	public String getSecureIdentity() {
		return identity;
	}

	/**
	 * Gets PSK secret for cluster internal connector.
	 * 
	 * @return PSK secret for cluster internal connector. Maybe {@code null}, if
	 *         encryption is not used.
	 */
	public SecretKey getSecretKey() {
		return SecretUtil.create(secret);
	}

	/**
	 * Enable MAC for cluster messages.
	 * 
	 * @return {@code true}, to enable MAC for forwarded and backwarded
	 *         messages, {@code false}, otherwise.
	 */
	public boolean useClusterMac() {
		return clusterMac;
	}

	/**
	 * Enable backward messages.
	 * 
	 * @return {@code true}, to send outgoing messages back via original
	 *         receiving connector (router), {@code false}, to send outgoing
	 *         messages directly.
	 */
	public boolean useBackwardMessages() {
		return backwardMessages;
	}

	/**
	 * @return a copy of this configuration
	 */
	@Override
	protected Object clone() {
		DtlsClusterConnectorConfig cloned = new DtlsClusterConnectorConfig();
		cloned.address = address;
		cloned.identity = identity;
		cloned.secret = SecretUtil.create(secret);
		cloned.clusterMac = clusterMac;
		cloned.backwardMessages = backwardMessages;
		return cloned;
	}

	/**
	 * Create builder.
	 * 
	 * @return created builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Create builder initialized with provided configuration.
	 * 
	 * @param config configuration for initialization
	 * @return created and initialized builder.
	 */
	public static Builder builder(DtlsClusterConnectorConfig config) {
		return new Builder(config);
	}

	/**
	 * Builder for cluster connector configuration.
	 */
	public final static class Builder {

		/**
		 * Current configuration.
		 */
		private DtlsClusterConnectorConfig config;

		/**
		 * Create new builder.
		 */
		public Builder() {
			config = new DtlsClusterConnectorConfig();
		}

		/**
		 * Create new builder initialized with provided configuration.
		 * 
		 * @param initialConfiguration configuration for initialization
		 */
		public Builder(DtlsClusterConnectorConfig initialConfiguration) {
			config = (DtlsClusterConnectorConfig) initialConfiguration.clone();
		}

		/**
		 * Sets local socket address for internal cluster connector.
		 * 
		 * @param address local socket address for internal cluster connector.
		 * @return this builder for command chaining
		 */
		public Builder setAddress(InetSocketAddress address) {
			config.address = address;
			return this;
		}

		/**
		 * Set PSK credentials.
		 * 
		 * @param identity PSK identity for cluster internal connector. If
		 *            {@code null}, encryption is disabled. In that case the
		 *            secret must also be {@code null}.
		 * @param secret PSK secret for cluster internal connector. The secret
		 *            is copied, therefore the caller is intended to delete it
		 *            afterwards. If {@code null}, encryption is disabled. In
		 *            that case the identity must also be {@code null}.
		 * @return this builder for command chaining
		 * @throws IllegalArgumentException if one argument is {@code null} and
		 *             the other not.
		 */
		public Builder setSecure(String identity, SecretKey secret) {
			if (identity == null && secret != null) {
				throw new IllegalArgumentException("No identity but secret!");
			}
			if (identity != null && secret == null) {
				throw new IllegalArgumentException("No secret but identity!");
			}
			if (config.secret != null) {
				SecretUtil.destroy(config.secret);
			}
			config.identity = identity;
			config.secret = SecretUtil.create(secret);
			return this;
		}

		/**
		 * Enable to send forwarded and backwarded messages protected with a
		 * MAC.
		 * 
		 * Enable encryption using {@link #setSecure(String, SecretKey)} enables
		 * the MAC as default. Without encryption, using a MAC for forwarded and
		 * backwarded messages is not possible.
		 * 
		 * @param enable {@code true}, to use MAC, {@code false}, otherwise.
		 * @return this builder for command chaining
		 */
		public Builder setClusterMac(Boolean enable) {
			config.clusterMac = enable;
			return this;
		}

		/**
		 * Enable to send outgoing messages back via original receiving
		 * connector (router).
		 * 
		 * @param enable {@code true}, to send outgoing messages back via
		 *            original receiving connector (router), {@code false}, to
		 *            send outgoing messages directly.
		 * @return this builder for command chaining
		 */
		public Builder setBackwardMessage(Boolean enable) {
			config.backwardMessages = enable;
			return this;
		}

		/**
		 * Returns a potentially incomplete configuration. Only fields set by
		 * users are affected, there is no default value, no consistency check.
		 * To get a full usable {@link DtlsConnectorConfig} use {@link #build()}
		 * instead.
		 * 
		 * @return the incomplete Configuration
		 */
		public DtlsClusterConnectorConfig getIncompleteConfig() {
			return config;
		}

		/**
		 * Creates an instance of {@code DtlsClusterConnectorConfig} based
		 * on the properties set on this builder.
		 * <p>
		 * Fills in default values.
		 * 
		 * @return the configuration object
		 * @throws IllegalStateException if
		 *             {@link DtlsClusterConnectorConfig#address} wasn't
		 *             provided.
		 */
		public DtlsClusterConnectorConfig build() {
			if (config.address == null) {
				throw new IllegalStateException("Local cluster socker address missing!");
			}
			if (config.clusterMac == Boolean.TRUE && config.identity == null) {
				throw new IllegalStateException("MAC for cluster traffic requires enabled encryption!");
			}
			if (config.backwardMessages == null) {
				config.backwardMessages = Boolean.TRUE;
			}
			if (config.clusterMac == null) {
				config.clusterMac = config.identity != null;
			}
			return config;
		}

	}
}
