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
package org.eclipse.californium.cloud;

import java.net.InetSocketAddress;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointObserver;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.DtlsHealth;
import org.eclipse.californium.scandium.DtlsHealthLogger;
import org.eclipse.californium.unixhealth.NetSocketHealthLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Register {@link Endpoint}s at a {@link NetSocketHealthLogger}.
 * <p>
 * Registers the local addresses of {@link Endpoint}s at the
 * {@link NetSocketHealthLogger} to read the related udp message drops.
 * Registers also external {@link SimpleCounterStatistic}, if available, to
 * forward the read number of dropped messages. That enables currently the
 * {@link DtlsHealthLogger} to display the dropped UDP messages as well.
 * 
 * @since 3.12
 */
public class EndpointNetSocketObserver implements EndpointObserver {

	private static final Logger LOGGER = LoggerFactory.getLogger(EndpointNetSocketObserver.class);

	/**
	 * Net socket statistic to register endpoints.
	 */
	private final NetSocketHealthLogger netSocketStatistic;

	/**
	 * Create net socket endpoint observer.
	 * 
	 * @param netSocketStatistic net-socket statistic to register endpoints
	 */
	public EndpointNetSocketObserver(NetSocketHealthLogger netSocketStatistic) {
		this.netSocketStatistic = netSocketStatistic;
	}

	/**
	 * Add endpoint.
	 * <p>
	 * Add enpoint's local address to UDP network statistic and forward parts of
	 * that statistic to the endpoint.
	 * 
	 * @param endpoint endpoint to add
	 */
	public void add(Endpoint endpoint) {
		InetSocketAddress address = endpoint.getAddress();
		if (netSocketStatistic.add(address, getExternalStatistic(endpoint))) {
			LOGGER.debug("added {}", address);
		} else {
			LOGGER.debug("enabled {}", address);
		}
	}

	/**
	 * Remove endpoint.
	 * <p>
	 * Remove enpoint's local address from UDP network statistic.
	 * 
	 * @param endpoint endpoint to remove
	 */
	public void remove(Endpoint endpoint) {
		InetSocketAddress address = endpoint.getAddress();
		netSocketStatistic.remove(address);
		LOGGER.debug("removed {}", address);
	}

	@Override
	public void stopped(Endpoint endpoint) {
		remove(endpoint);
	}

	@Override
	public void started(Endpoint endpoint) {
		add(endpoint);
	}

	@Override
	public void destroyed(Endpoint endpoint) {
		remove(endpoint);
	}

	/**
	 * Get net socket health statistic.
	 * 
	 * @return net socket health statistic
	 */
	public NetSocketHealthLogger getNetSocketHealth() {
		return netSocketStatistic;
	}

	/**
	 * Get external statistic to register at {@link NetSocketHealthLogger} in
	 * order to forward the number of dropped UDP messages.
	 * 
	 * @param endpoint endpoint to forward the dropped UDP message statistic
	 * @return external statistic to register for forwarding the dropped UDP
	 *         message statistic
	 */
	protected SimpleCounterStatistic getExternalStatistic(Endpoint endpoint) {
		CounterStatisticManager dtlsStatisticManager = getDtlsStatisticManager(endpoint);
		return dtlsStatisticManager != null ? dtlsStatisticManager.getByKey(DtlsHealthLogger.DROPPED_UDP_MESSAGES)
				: null;
	}

	/**
	 * Get statistic manager of endpoint.
	 * 
	 * @param endpoint endpoint
	 * @return statistic manager of endpoint
	 */
	public static CounterStatisticManager getDtlsStatisticManager(Endpoint endpoint) {
		if (endpoint instanceof CoapEndpoint) {
			Connector connector = ((CoapEndpoint) endpoint).getConnector();
			if (connector instanceof DTLSConnector) {
				DtlsHealth healthHandler = ((DTLSConnector) connector).getHealthHandler();
				if (healthHandler instanceof CounterStatisticManager) {
					return (CounterStatisticManager) healthHandler;
				}
			}
		}
		return null;
	}

}
