package org.eclipse.californium.core.identifier;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.CorrelationContext;

public interface IdentifierFactory {

	CorrelationContext createContext(EndpointIdentifier identifier);

	EndpointIdentifier extractIdentifier(CorrelationContext context, InetSocketAddress address);
}
