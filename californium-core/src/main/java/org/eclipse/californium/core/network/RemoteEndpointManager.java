package org.eclipse.californium.core.network;

import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.Map;

import org.eclipse.californium.core.network.config.NetworkConfig;

public class RemoteEndpointManager {

	// Maximum amount of destinations for which remote endpoint objects are maintained
	private final int MAX_REMOTE_ENDPOINTS = 10;
	
	/** The list of remote endpoints */
	private LimitedRemoteEndpointHashmap<InetAddress,RemoteEndpoint> remoteEndpointsList = new LimitedRemoteEndpointHashmap<InetAddress,RemoteEndpoint>(MAX_REMOTE_ENDPOINTS);//ArrayList<RemoteEndpoint>(0);

	/** The configuration */ 
	private NetworkConfig config;
	
	/**
	 * The RemoteEndpointManager is responsible for creating a new RemoteEndpoint object when exchanges with a 
	 * new destination endpoint are initiated and managing existing ones.
	 * 
	 * @param config : The network parameter configuration
	 */
	public RemoteEndpointManager(NetworkConfig config) {
		this.config = config;
	}
		
	/**
	 * 
	 * @param remotePort	The port associated to the destination endpoint 
	 * @param remoteAddress The IP-Address associated to the destination endpoint
	 * @return
	 */
	public RemoteEndpoint getRemoteEndpoint(Exchange exchange){ //int remotePort, InetAddress remoteAddress){
		
		InetAddress remoteAddress = exchange.getRequest().getDestination();
		int remotePort = exchange.getRequest().getDestinationPort();
		
		// TODO: One IP-Address is considered to be a destination endpoint, for higher granularity (portnumber) changes are necessary
		if (!remoteEndpointsList.containsKey(remoteAddress)){
			RemoteEndpoint unusedRemoteEndpoint = new RemoteEndpoint(remotePort, remoteAddress, config);
			remoteEndpointsList.put(remoteAddress,unusedRemoteEndpoint);
			
			System.out.println("Number of RemoteEndpoint objects stored:" + remoteEndpointsList.size());
		}
		
		return remoteEndpointsList.get(remoteAddress);
		
		
		//Check if this combination of InetAddress and Port is available and return the remote endpoint if so
//			for (int i = 0; i < remoteEndpointsList.size(); i++) {		
//				if(remoteAddress.equals(remoteEndpointsList.get(i).getRemoteAddress())){
//					if(remotePort ==  remoteEndpointsList.get(i).getRemotePort()){
//						//System.out.println("Found matching port: " + remotePort);
//						//System.out.println("Found matching Address: " + remoteAddress.toString());
//						return remoteEndpointsList.get(i);
//				    }
//				}
//			}			
			
		// No remoteEndpoint with this combination of Address and Port available -> Create a new entry
//			RemoteEndpoint unusedRemoteEndpoint = new RemoteEndpoint(remotePort, remoteAddress, config);
//			remoteEndpointsList.add(unusedRemoteEndpoint);
//			
//			//System.out.println("Created remote Endpoint for address " + unusedRemoteEndpoint.getRemoteAddress().toString());
//			//System.out.println("Amount of stored remote endpoints: " + remoteEndpointsList.size());
//		
//			return unusedRemoteEndpoint;
	}
	
	public class LimitedRemoteEndpointHashmap<K, V> extends LinkedHashMap<K, V> {
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
