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
package org.eclipse.californium.cli.tcp.netty;

import java.util.concurrent.ExecutorService;

import org.eclipse.californium.cli.CliConnectorFactory;
import org.eclipse.californium.cli.ClientBaseConfig;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.tcp.netty.TcpClientConnector;

/**
 * TCP connector factory for CLI.
 * 
 * @since 2.4
 */
public class TcpConnectorFactory implements CliConnectorFactory {

	@Override
	public Connector create(ClientBaseConfig clientConfig, ExecutorService executor) {
		return new TcpClientConnector(clientConfig.configuration);
	}

}
