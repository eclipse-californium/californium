package org.eclipse.californium.elements;

import java.net.InetSocketAddress;

public class EndpointContextBuilder {
	public static final InetSocketAddress ADDRESS = new InetSocketAddress(0);

	public static DtlsEndpointContext createDtlsEndpointContext(String sessionId, String epoch, String cipher) {
		return new DtlsEndpointContext(ADDRESS, null, sessionId, epoch, cipher);
	}

	public static TcpEndpointContext createTcpEndpointContext(String connectionId) {
		return new TcpEndpointContext(ADDRESS, connectionId);
	}

	public static MapBasedEndpointContext createMapBasedEndpointContext() {
		return new MapBasedEndpointContext(ADDRESS, null);
	}
	
}
