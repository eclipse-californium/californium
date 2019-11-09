/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.network.config;

/**
 * Handler for custom setup of default network configuration. Called after
 * {@link NetworkConfigDefaults#setDefaults(NetworkConfig)}.
 */
public interface NetworkConfigDefaultHandler {

	/**
	 * Apply custom defaults.
	 * 
	 * @param config network configuration to be filled with custom defaults.
	 */
	void applyDefaults(NetworkConfig config);
}
