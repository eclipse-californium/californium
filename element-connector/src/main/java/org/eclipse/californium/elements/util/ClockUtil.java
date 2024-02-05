/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
package org.eclipse.californium.elements.util;

import java.util.concurrent.TimeUnit;

/**
 * Clock utility. Provides a {@linkplain ClockUtil#handler handler}.
 * 
 * Intended to be used for system as android, where {@link System#nanoTime()}
 * reflects the system uptime without system sleep times. Android devices, which
 * want to use californium timer's (e.g. auto resumption or deduplication) in
 * sleep times, must set their handler and provide the proper expired
 * nanoseconds. This will not wake up any californium timer in time, but it
 * expires them on then next wake up. Not used for schedule timed of schedule
 * timer e.g. {@link ExecutorsUtil}.
 */
public class ClockUtil {

	/**
	 * Handler to return the expired realtime in nanoseconds.
	 */
	public interface Realtime {

		/**
		 * Get the system specific expired realtime in nanoseconds.
		 * 
		 * @return expired realtime in nanoseconds.
		 */
		long nanoRealtime();
	}

	/**
	 * Handler for system specific expired realtime in nanoseconds. Default
	 * calls {@link System#nanoTime()}. Overridden calling
	 * {@link #setRealtimeHandler(Realtime)} with a system specific
	 * implementation.
	 */
	private static volatile Realtime handler = new Realtime() {

		@Override
		public long nanoRealtime() {
			return System.nanoTime();
		}
	};

	/**
	 * Set handler system specific expired realtime in nanoseconds.
	 * 
	 * @param systemHandler system specific expired realtime in nanoseconds.
	 * @throws NullPointerException if systemHandler is {@code null}
	 */
	public static void setRealtimeHandler(Realtime systemHandler) {
		if (systemHandler == null) {
			throw new NullPointerException("realtime system handler must not be null!");
		}
		handler = systemHandler;
	}

	/**
	 * Get expired realtime in nanoseconds.
	 * 
	 * If no system specific handler was set before, the default handler calling
	 * {@link System#nanoTime()} is used.
	 * 
	 * @return expired realtime in nanoseconds
	 */
	public static long nanoRealtime() {
		return handler.nanoRealtime();
	}

	/**
	 * Calculate the delta from the provided past nano-realtime.
	 * 
	 * @param pastNanoRealtime past value of {@link #nanoRealtime()}. Maybe
	 *            {@code 0}, if the past nano-realtime isn't available.
	 * @param unit unit of result
	 * @return the difference of the current nano-realtime to the provided one,
	 *         or {@code 0}, if {@code 0} is provided.
	 * @since 3.11
	 */
	public static long delta(long pastNanoRealtime, TimeUnit unit) {
		if (pastNanoRealtime > 0) {
			return unit.convert(handler.nanoRealtime() - pastNanoRealtime, TimeUnit.NANOSECONDS);
		}
		return 0;
	}
}
