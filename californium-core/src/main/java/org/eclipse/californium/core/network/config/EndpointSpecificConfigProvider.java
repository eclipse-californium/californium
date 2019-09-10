package org.eclipse.californium.core.network.config;

import org.eclipse.californium.elements.EndpointContext;

/**
 * Generic interface for endpoint specific configuration providers.
 * Looks up config dynamically based on on endpoint context.
 *
 * Providers can be registered with {@link NetworkConfig#addEndpointSpecificConfigProvider(Class, EndpointSpecificConfigProvider)}
 *
 */
public interface EndpointSpecificConfigProvider<T> {
	/**
	 * Gets configuration parameters specific to the endpoint
	 *
	 * @param endpointContext endpoint context in the exchange
	 * @return configuration for endpoint for specific parameters
	 */
	T getConfigForEndpoint(EndpointContext endpointContext);
}
