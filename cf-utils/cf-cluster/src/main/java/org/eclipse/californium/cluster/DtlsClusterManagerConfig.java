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
package org.eclipse.californium.cluster;

import org.eclipse.californium.scandium.config.DtlsConnectorConfig;

/**
 * DTLS cluster manager configuration.
 * 
 * @since 2.5
 */
public final class DtlsClusterManagerConfig {

	/**
	 * Default timer interval in milliseconds.
	 * 
	 * @see #timerIntervalMillis
	 */
	public static final long DEFAULT_TIMER_INTERVAL_MILLIS = 2000;
	/**
	 * Default refresh interval in milliseconds.
	 * 
	 * @see #refreshIntervalMillis
	 */
	public static final long DEFAULT_REFRESH_INTERVAL_MILLIS = 6000;
	/**
	 * Default discover interval in milliseconds.
	 * 
	 * @see #discoverIntervalMillis
	 */
	public static final long DEFAULT_DISCOVER_INTERVAL_MILLIS = 30000;

	/**
	 * Timer interval in milliseconds.
	 */
	private Long timerIntervalMillis;
	/**
	 * Refresh interval in milliseconds for cluster nodes updates.
	 */
	private Long refreshIntervalMillis;
	/**
	 * Expiration time in millisecond.
	 * 
	 * Time after start of refreshing.
	 */
	private Long expirationTimeMillis;
	/**
	 * Discover interval in milliseconds.
	 */
	private Long discoverIntervalMillis;

	/**
	 * Get timer interval in milliseconds.
	 * 
	 * The other time of this configuration are checked with this granularity.
	 * 
	 * @return timer interval in milliseconds
	 */
	public long getTimerIntervalMillis() {
		return timerIntervalMillis;
	}

	/**
	 * Get refresh interval in milliseconds.
	 * 
	 * If this time has elapsed since the last successful refresh, a refresh
	 * message is sent to the other node. A response of the other node will
	 * reset the time.
	 * 
	 * @return refresh interval in milliseconds.
	 */
	public long getRefreshIntervalMillis() {
		return refreshIntervalMillis;
	}

	/**
	 * Get expiration time in milliseconds.
	 * 
	 * Time to expire node after starting to refresh.
	 * 
	 * @return expiration time in milliseconds
	 */
	public long getExpirationTimeMillis() {
		return expirationTimeMillis;
	}

	/**
	 * Discover interval in milliseconds.
	 * 
	 * @return discover interval in milliseconds
	 */
	public long getDiscoverIntervalMillis() {
		return discoverIntervalMillis;
	}

	/**
	 * @return a copy of this configuration
	 */
	@Override
	protected Object clone() {
		DtlsClusterManagerConfig cloned = new DtlsClusterManagerConfig();
		cloned.timerIntervalMillis = timerIntervalMillis;
		cloned.refreshIntervalMillis = refreshIntervalMillis;
		cloned.expirationTimeMillis = expirationTimeMillis;
		cloned.discoverIntervalMillis = discoverIntervalMillis;
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
	public static Builder builder(DtlsClusterManagerConfig config) {
		return new Builder(config);
	}

	/**
	 * Builder for cluster manager configuration.
	 */
	public final static class Builder {

		/**
		 * Current configuration.
		 */
		private DtlsClusterManagerConfig config;

		/**
		 * Create new builder.
		 */
		public Builder() {
			config = new DtlsClusterManagerConfig();
		}

		/**
		 * Create new builder initialized with provided configuration.
		 * 
		 * @param initialConfiguration configuration for initialization
		 */
		public Builder(DtlsClusterManagerConfig initialConfiguration) {
			config = (DtlsClusterManagerConfig) initialConfiguration.clone();
		}

		/**
		 * Sets the timer interval in milliseconds.
		 * 
		 * @param timerIntervalMillis the timer interval in milliseconds
		 * @return this builder for command chaining
		 */
		public Builder setTimerIntervalMillis(Long timerIntervalMillis) {
			config.timerIntervalMillis = timerIntervalMillis;
			return this;
		}

		/**
		 * Sets the refresh interval in milliseconds.
		 * 
		 * @param refreshIntervalMillis the refresh interval in milliseconds
		 * @return this builder for command chaining
		 */
		public Builder setRefreshIntervalMillis(Long refreshIntervalMillis) {
			config.refreshIntervalMillis = refreshIntervalMillis;
			return this;
		}

		/**
		 * Sets the expiration time in milliseconds.
		 * 
		 * @param expirationTimeMillis the expiration time in milliseconds
		 * @return this builder for command chaining
		 */
		public Builder setExpirationTimeMillis(Long expirationTimeMillis) {
			config.expirationTimeMillis = expirationTimeMillis;
			return this;
		}

		/**
		 * Sets the discover interval in milliseconds.
		 * 
		 * @param discoverIntervalMillis the discover interval in milliseconds
		 * @return this builder for command chaining
		 */
		public Builder setDiscoverIntervalMillis(Long discoverIntervalMillis) {
			config.discoverIntervalMillis = discoverIntervalMillis;
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
		public DtlsClusterManagerConfig getIncompleteConfig() {
			return config;
		}

		/**
		 * Creates an instance of <code>DtlsClusterManagerConfig</code> based on
		 * the properties set on this builder.
		 * <p>
		 * Fills in default values.
		 * 
		 * @return the configuration object
		 */
		public DtlsClusterManagerConfig build() {
			// set default values
			if (config.timerIntervalMillis == null) {
				config.timerIntervalMillis = DEFAULT_TIMER_INTERVAL_MILLIS;
			}
			if (config.refreshIntervalMillis == null) {
				config.refreshIntervalMillis = DEFAULT_REFRESH_INTERVAL_MILLIS;
			}
			if (config.expirationTimeMillis == null) {
				config.expirationTimeMillis = config.timerIntervalMillis * 2;
			}
			if (config.discoverIntervalMillis == null) {
				config.discoverIntervalMillis = DEFAULT_DISCOVER_INTERVAL_MILLIS;
			}
			return config;
		}

	}
}
