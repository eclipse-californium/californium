/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations GmbH - initial implementation. 
 *                                      add support for correlation context
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import io.netty.channel.Channel;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.TcpCorrelationContext;

/**
 * Utils for building for TCP correlation context and principal from
 * channel. To be extended in the future to support TLS also.
 */
public class NettyContextUtils {

	private static final Logger LOGGER = Logger.getLogger(NettyContextUtils.class.getName());
	private static final Level LEVEL = Level.FINER;

	/**
	 * Build correlation context related to the provided channel.
	 * 
	 * @param channel channel of correlation context
	 * @return correlation context
	 */
	public static CorrelationContext buildCorrelationContext(Channel channel) {
		String id = channel.id().asShortText();
		LOGGER.log(LEVEL, "TCP({0})", id);
		return new TcpCorrelationContext(id);
	}
}
