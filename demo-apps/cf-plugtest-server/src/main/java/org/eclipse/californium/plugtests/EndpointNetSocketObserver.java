/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import java.net.InetSocketAddress;

import org.eclipse.californium.core.coap.CoAP;
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
 * 
 * Registers the local addresses of {@link Endpoint}s at the
 * {@link NetSocketHealthLogger} to read the related udp message drops.
 * Registers also external {@link SimpleCounterStatistic}, if available, to
 * forward the read number of dropped messages. That enables currently the
 * {@link DtlsHealthLogger} to display the dropped udp messages as well.
 * 
 * @since 3.1
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

	@Override
	public void stopped(Endpoint endpoint) {
		InetSocketAddress address = getAddress(endpoint);
		if (address != null) {
			netSocketStatistic.remove(address);
			LOGGER.debug("removed {}", address);
		}
	}

	@Override
	public void started(Endpoint endpoint) {
		InetSocketAddress address = getAddress(endpoint);
		if (address != null) {
			if (netSocketStatistic.add(address, getExternalStatistic(endpoint))) {
				LOGGER.debug("added {}", address);
			} else {
				LOGGER.debug("enabled {}", address);
			}
		}
	}

	@Override
	public void destroyed(Endpoint endpoint) {
		InetSocketAddress address = getAddress(endpoint);
		if (address != null) {
			netSocketStatistic.remove(address);
			LOGGER.debug("removed {}", address);
		}
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
	 * Get external statistic to register at {@link NetSocketHealthLogger} in order
	 * to forward the number of dropped udp messages..
	 * 
	 * @param endpoint endpoint
	 * @return external statistic to register
	 */
	protected SimpleCounterStatistic getExternalStatistic(Endpoint endpoint) {
		CounterStatisticManager dtlsStatisticManager = getDtlsStatisticManager(endpoint);
		return dtlsStatisticManager != null ? dtlsStatisticManager.getByKey(DtlsHealthLogger.DROPPED_UDP_MESSAGES)
				: null;
	}

	/**
	 * Get local address to register at {@link NetSocketHealthLogger}.
	 * 
	 * @param endpoint endpoint
	 * @return local address to register
	 */
	protected InetSocketAddress getAddress(Endpoint endpoint) {
		String scheme = endpoint.getUri().getScheme();
		if (CoAP.isUdpScheme(scheme)) {
			return endpoint.getAddress();
		} else {
			return null;
		}
	}

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
