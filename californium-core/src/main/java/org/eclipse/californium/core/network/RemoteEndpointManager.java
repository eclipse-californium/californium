/*******************************************************************************
 * Copyright (c) 2015 Wireless Networks Group, UPC Barcelona and i2CAT.
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
 *    August Betzler    – CoCoA implementation
 *    Matthias Kovatsch - Embedding of CoCoA in Californium
 ******************************************************************************/

package org.eclipse.californium.core.network;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.LinkedHashMap;
import java.util.Map;

import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.ReliabilityLayerParameters;

public class RemoteEndpointManager {

	// Maximum amount of destinations for which remote endpoint objects are maintained
	private final int MAX_REMOTE_ENDPOINTS = 10;
	
	/** The list of remote endpoints */
	private LimitedRemoteEndpointHashmap<InetAddress,RemoteEndpoint> remoteEndpointsList = new LimitedRemoteEndpointHashmap<InetAddress,RemoteEndpoint>(MAX_REMOTE_ENDPOINTS);//ArrayList<RemoteEndpoint>(0);

	/** Default reliability layer parameters from {@link NetworkConfig} */
	private final ReliabilityLayerParameters defaultReliabilityLayerParameters;

	/**
	 * The RemoteEndpointManager is responsible for creating a new RemoteEndpoint object when exchanges with a 
	 * new destination endpoint are initiated and managing existing ones.
	 * 
	 * @param config the network parameter configuration
	 */
	public RemoteEndpointManager(NetworkConfig config) {
		defaultReliabilityLayerParameters = ReliabilityLayerParameters.builder().applyConfig(config).build();
	}

	/**
	 * Returns the endpoint responsible for the given exchange.
	 * @param exchange the exchange
	 * @return the endpoint for the exchange
	 */
	public RemoteEndpoint getRemoteEndpoint(Exchange exchange){ //int remotePort, InetAddress remoteAddress){

		InetSocketAddress remoteSocketAddress = exchange.getRequest().getDestinationContext().getPeerAddress();
		InetAddress remoteAddress = remoteSocketAddress.getAddress();
		int remotePort = remoteSocketAddress.getPort();

		// TODO: One IP-Address is considered to be a destination endpoint, for higher granularity (portnumber) changes are necessary
		if (!remoteEndpointsList.containsKey(remoteAddress)){
			ReliabilityLayerParameters parameters = exchange.getRequest().getReliabilityLayerParameters();
			if (parameters == null) {
				parameters = defaultReliabilityLayerParameters;
			}
			RemoteEndpoint unusedRemoteEndpoint = new RemoteEndpoint(remotePort, remoteAddress, parameters);
			remoteEndpointsList.put(remoteAddress,unusedRemoteEndpoint);
			
			//System.out.println("Number of RemoteEndpoint objects stored:" + remoteEndpointsList.size());
		}

		return remoteEndpointsList.get(remoteAddress);
	}
	
	public class LimitedRemoteEndpointHashmap<K, V> extends LinkedHashMap<K, V> {

		private static final long serialVersionUID = -7855412701242966797L;
		private final int maxSize;

	    public LimitedRemoteEndpointHashmap(int maxSize) {
	        this.maxSize = maxSize;
	    }

	    @Override
	    protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
	        return size() > maxSize;
	    }
	}
}
