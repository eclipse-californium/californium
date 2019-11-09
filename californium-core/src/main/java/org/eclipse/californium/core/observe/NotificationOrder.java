/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial API and implementation
 *                                      split from ObserveNotificationOrderer
 *******************************************************************************/
package org.eclipse.californium.core.observe;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.util.ClockUtil;

/**
 * The NotificationOrderer holds the state of an observe relation such as the
 * timeout of the last notification and the current number.
 */
public class NotificationOrder {

	/** The observe number */
	protected final Integer number;

	/** The timestamp of the response */
	protected final long nanoTimestamp;

	/**
	 * Creates a new notification order for a given notification.
	 * 
	 * @param observe observe of the notification, or {@code null}, if order is
	 *            not related to a notification.
	 */
	public NotificationOrder(Integer observe) {
		this(observe, ClockUtil.nanoRealtime());
	}

	/**
	 * Creates a new notification order for a given notification.
	 * 
	 * @param observe observe of the notification, or {@code null}, if order is
	 *            not related to a notification.
	 * @param nanoTime receive time of notification
	 */
	public NotificationOrder(Integer observe, long nanoTime) {
		number = observe;
		nanoTimestamp = nanoTime;
	}

	/**
	 * Returns the notification number.
	 * 
	 * @return the notification number, or {@code null}, if order is not related
	 *         to a notification.
	 */
	public Integer getObserve() {
		return number;
	}

	/**
	 * Test, if the provided notification is newer than the current one.
	 * 
	 * @param response the notification
	 * @return {@code true} if the notification is new
	 */
	public synchronized boolean isNew(Response response) {

		Integer observe = response.getOptions().getObserve();
		if (observe == null) {
			// this is a final response, e.g. error or proactive cancellation
			return true;
		}

		return isNew(nanoTimestamp, number, ClockUtil.nanoRealtime(), observe);
	}

	/**
	 * Compare order of notifications.
	 * 
	 * @param T1 nano realtimestamp of first notification
	 * @param V1 observe number of first notification
	 * @param T2 nano realtimestamp of second notification
	 * @param V2 observe number of second notification
	 * @return {@code true}, if second notification is newer.
	 */
	public static boolean isNew(long T1, int V1, long T2, int V2) {
		// Multiple responses with different notification numbers might
		// arrive and be processed by different threads. We have to
		// ensure that only the most fresh one is being delivered.
		// We use the notation from the observe draft-08.
		if (V1 < V2 && (V2 - V1) < (1L << 23) || V1 > V2 && (V1 - V2) > (1L << 23)
				|| T2 > (T1 + TimeUnit.SECONDS.toNanos(128))) {
			return true;
		} else {
			return false;
		}
	}
}
