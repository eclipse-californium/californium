/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
package org.eclipse.californium.cluster.config;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TimeDefinition;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.elements.config.Configuration.ModuleDefinitionsProvider;

/**
 * Configuration definitions for dtls cluster manager.
 * 
 * @since 3.0
 */
public final class DtlsClusterManagerConfig {

	public static final String MODULE = "CLUSTER_MGMT.";

	/**
	 * Default timer interval in milliseconds.
	 * 
	 * @see #TIMER_INTERVAL
	 */
	public static final long DEFAULT_TIMER_INTERVAL_MILLIS = 2000;
	/**
	 * Default refresh interval in milliseconds.
	 * 
	 * @see #REFRESH_INTERVAL
	 */
	public static final long DEFAULT_REFRESH_INTERVAL_MILLIS = 4000;
	/**
	 * Default discover interval in milliseconds.
	 * 
	 * @see #DISCOVER_INTERVAL
	 */
	public static final long DEFAULT_DISCOVER_INTERVAL_MILLIS = 10000;

	/**
	 * Timer interval for cluster management.
	 * 
	 * Interval to check for refreshing nodes, expired nodes, and discovering
	 * new nodes.
	 */
	public static final TimeDefinition TIMER_INTERVAL = new TimeDefinition(MODULE + "TIMER_INTERVAL",
			"Cluster-Manager timer interval.", DEFAULT_TIMER_INTERVAL_MILLIS, TimeUnit.MILLISECONDS);
	/**
	 * Refresh interval for cluster management to probe known nodes.
	 * 
	 * Checked with {@link #TIMER_INTERVAL}.
	 */
	public static final TimeDefinition REFRESH_INTERVAL = new TimeDefinition(MODULE + "REFRESH_INTERVAL",
			"Cluster-Manager refresh interval for nodes.", DEFAULT_REFRESH_INTERVAL_MILLIS, TimeUnit.MILLISECONDS);
	/**
	 * Discover interval for cluster management to search for new nodes.
	 * 
	 * Checked with {@link #TIMER_INTERVAL}.
	 */
	public static final TimeDefinition DISCOVER_INTERVAL = new TimeDefinition(MODULE + "DISCOVER_INTERVAL",
			"Cluster-Manager discover interval to detect new nodes.", DEFAULT_DISCOVER_INTERVAL_MILLIS,
			TimeUnit.MILLISECONDS);
	/**
	 * Time to expire not responding nodes.
	 * 
	 * Checked with {@link #TIMER_INTERVAL}.
	 */
	public static final TimeDefinition EXPIRATION_TIME = new TimeDefinition(MODULE + "EXPIRATION_TIME",
			"Cluster-Manager time to expire not responding nodes.",
			DEFAULT_TIMER_INTERVAL_MILLIS + DEFAULT_REFRESH_INTERVAL_MILLIS, TimeUnit.MILLISECONDS);

	public static final ModuleDefinitionsProvider DEFINITIONS = new ModuleDefinitionsProvider() {

		@Override
		public String getModule() {
			return MODULE;
		}

		@Override
		public void applyDefinitions(Configuration config) {

			config.set(TIMER_INTERVAL, DEFAULT_TIMER_INTERVAL_MILLIS, TimeUnit.MILLISECONDS);
			config.set(REFRESH_INTERVAL, DEFAULT_REFRESH_INTERVAL_MILLIS, TimeUnit.MILLISECONDS);
			config.set(DISCOVER_INTERVAL, DEFAULT_DISCOVER_INTERVAL_MILLIS, TimeUnit.MILLISECONDS);
			config.set(EXPIRATION_TIME, DEFAULT_TIMER_INTERVAL_MILLIS + DEFAULT_REFRESH_INTERVAL_MILLIS,
					TimeUnit.MILLISECONDS);

		}
	};

	static {
		Configuration.addDefaultModule(DEFINITIONS);
	}

	/**
	 * Register definitions of this module to the default definitions. Register
	 * the required definitions of {@link DtlsConfig} and {@link SystemConfig}
	 * as well.
	 */
	public static void register() {
		DtlsConfig.register();
	}
}
