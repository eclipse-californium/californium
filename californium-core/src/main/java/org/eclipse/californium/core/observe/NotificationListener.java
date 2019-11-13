/*******************************************************************************
 * Copyright (c) 2016 Sierra Wireless and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.observe;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;

/**
 * Client code can register a notification listener on an {@code Endpoint} in
 * order to be called back when notifications for observed resources are
 * received from peers.
 * <p>
 * Notification listeners are registered at a <em>global</em> level only, i.e.
 * the listener will be invoked for all notifications for all observed
 * resources. This is in contrast to the {@code CoapHandler} that client code
 * can register when invoking one of {@code CoapClient}'s methods and which is
 * called back for notifications for a particular observed resource only.
 * </p>
 */
public interface NotificationListener {

	/**
	 * Invoked when a notification for an observed resource has been received.
	 * 
	 * @param request
	 *            The original request that was used to establish the
	 *            observation.
	 * @param response
	 *            the notification.
	 */
	void onNotification(Request request, Response response);
}
