/*******************************************************************************
 * Copyright (c) 2016, 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation.
 *                                      Derived from NettyContextUtils.
 ******************************************************************************/
package org.eclipse.californium.elements.tcp.netty;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.TcpEndpointContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.channel.Channel;
import io.netty.util.AttributeKey;

/**
 * Util for building for TCP endpoint context from channel.
 */
public class TcpContextUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(TcpContextUtil.class);

	/**
	 * Key for TCP connect timestamp.
	 * 
	 * @since 3.0
	 */
	private static final AttributeKey<Long> connectTimestamp = AttributeKey.newInstance("connect_millis");

	/**
	 * Build endpoint context related to the provided channel.
	 * 
	 * @param channel channel of endpoint context
	 * @return endpoint context
	 */
	public EndpointContext buildEndpointContext(Channel channel) {
		InetSocketAddress address = (InetSocketAddress) channel.remoteAddress();
		String id = channel.id().asShortText();
		Long timestamp = channel.attr(connectTimestamp).get();
		if (timestamp == null) {
			timestamp = System.currentTimeMillis();
			channel.attr(connectTimestamp).set(timestamp);
		}
		EndpointContext context = new TcpEndpointContext(address, id, timestamp);
		LOGGER.debug("{}", context);
		return context;
	}
}
