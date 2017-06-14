package org.eclipse.californium.core.identifier;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.DtlsCorrelationContext;
import org.eclipse.californium.elements.MapBasedCorrelationContext;

public class DefaultIdentifierFactory implements IdentifierFactory {

	@Override
	public EndpointIdentifier extractIdentifier(CorrelationContext context, InetSocketAddress address) {
		if (context != null) {
			Object object = context.get(DtlsCorrelationContext.KEY_SESSION_ID);
			if (object != null) {
				return new SessionEndpointIdentifier((String) object);
			}
		}
		return new InetEndpointIdentifier(address);
	}

	@Override
	public CorrelationContext createContext(EndpointIdentifier identifier) {
		if (identifier == null)
			return null;

		MapBasedCorrelationContext context = new MapBasedCorrelationContext();
		if (identifier instanceof SessionEndpointIdentifier) {
			context.put(DtlsCorrelationContext.KEY_SESSION_ID, ((SessionEndpointIdentifier) identifier).getSessionId());
		}

		throw new IllegalStateException(
				String.format("Unsuppoted endpoint identifier  %s:%s", identifier.getClass(), identifier));
	}
}
