/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - derived from DatagramReader
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.Arrays;

import org.slf4j.Logger;

/**
 * FilteredLogger.
 * 
 * Reduces the logging messages to a maximum per period. Depending on the
 * logging backend and that's features, this filter may be disabled by the
 * env-variable or java-property "COAP_LOGGING_FILTER" with other value then
 * "true".
 * 
 * @since 3.0
 */
public class FilteredLogger {

	private static final boolean ENABLE = Boolean.FALSE
			.equals(StringUtil.getConfigurationBoolean("COAP_LOGGING_FILTER"));

	/**
	 * Logger to to log.
	 */
	private final Logger logger;
	/**
	 * Nanoseconds per period.
	 */
	private final long nanosPerPeriod;
	/**
	 * Maximum logging messages per period.
	 */
	private final long maxPerPeriod;
	/**
	 * Counter of current logging messages of period.
	 */
	private long counter;
	/**
	 * Nanoseconds of period's start.
	 */
	private long startNanos;

	/**
	 * Create logging filter.
	 * 
	 * @param logger logger to log
	 * @param maxPerPeriod maximum logging messages per period.
	 * @param nanosPerPeriod nanoseconds per period.
	 */
	public FilteredLogger(Logger logger, long maxPerPeriod, long nanosPerPeriod) {
		this.logger = logger;
		this.maxPerPeriod = maxPerPeriod;
		this.nanosPerPeriod = nanosPerPeriod;
		this.startNanos = ClockUtil.nanoRealtime();
	}

	/**
	 * Filter warn logging.
	 * 
	 * @param fmt format
	 * @param args arguments
	 */
	public void warn(String fmt, Object... args) {
		if (logger.isWarnEnabled()) {
			log(true, fmt, args);
		}
	}

	/**
	 * Filter info logging.
	 * 
	 * @param fmt format
	 * @param args arguments
	 */
	public void info(String fmt, Object... args) {
		if (logger.isInfoEnabled()) {
			log(false, fmt, args);
		}
	}

	private void log(boolean warn, String fmt, Object... args) {
		boolean info;
		Long extraInfo = null;
		if (ENABLE) {
			info = false;
			long now = ClockUtil.nanoRealtime();
			long time = nanosPerPeriod + startNanos - now;
			synchronized (this) {
				info = counter < maxPerPeriod;
				if (time > 0) {
					++counter;
				} else {
					startNanos = now;
					if (!info) {
						extraInfo = counter;
					}
					counter = 0;
				}
			}
		} else {
			info = true;
		}
		if (info) {
			if (warn) {
				logger.warn(fmt, args);
			} else {
				logger.info(fmt, args);
			}
		} else if (extraInfo != null) {
			int length = args.length;
			args = Arrays.copyOf(args, length + 1);
			args[length] = extraInfo;
			if (warn) {
				logger.warn(fmt + " ({} additional errors.)", args);
			} else {
				logger.info(fmt + " ({} additional errors.)", args);
			}
		}
	}
}
