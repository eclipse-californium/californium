/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.cli;

import java.util.concurrent.ExecutorService;

import org.eclipse.californium.elements.Connector;

/**
 * Connector factory to be used for CLI.
 * 
 * @since 2.4
 */
public interface CliConnectorFactory {

	/**
	 * Create connector.
	 * 
	 * @param clientConfig cli client config
	 * @param executor executor
	 * @return create connector
	 */
	Connector create(ClientBaseConfig clientConfig, ExecutorService executor);
}
