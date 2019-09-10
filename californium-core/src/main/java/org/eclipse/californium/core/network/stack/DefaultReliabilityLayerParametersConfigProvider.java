package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.network.config.EndpointSpecificConfigProvider;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.EndpointContext;

/**
 * Default config provider implementation for {@link ReliabilityLayerParameters}
 * <p>
 * delegates to the static values in {@link NetworkConfig}, see {@link ReliabilityLayerParameters.Builder#applyConfig(NetworkConfig)}
 */
public class DefaultReliabilityLayerParametersConfigProvider implements EndpointSpecificConfigProvider<ReliabilityLayerParameters> {
	private final ReliabilityLayerParameters reliabilityLayerParameters;

	public DefaultReliabilityLayerParametersConfigProvider(NetworkConfig config) {
		reliabilityLayerParameters = ReliabilityLayerParameters.builder().applyConfig(config).build();
	}

	@Override
	public ReliabilityLayerParameters getConfigForEndpoint(EndpointContext endpointContext) {
		return reliabilityLayerParameters;
	}
}
