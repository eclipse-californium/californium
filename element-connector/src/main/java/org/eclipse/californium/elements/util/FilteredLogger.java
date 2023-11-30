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
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

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

	private static final boolean ENABLE = !Boolean.FALSE
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
	 * @deprecated use {@link #FilteredLogger(String, long, long)} instead.
	 */
	@Deprecated
	public FilteredLogger(Logger logger, long maxPerPeriod, long nanosPerPeriod) {
		this(logger, maxPerPeriod, nanosPerPeriod, TimeUnit.NANOSECONDS);
	}

	/**
	 * Create logging filter.
	 * 
	 * @param logger logger to log
	 * @param maxPerPeriod maximum logging messages per period.
	 * @param period period in units
	 * @param unit time unit of the period
	 * @since 3.5
	 * @deprecated use {@link #FilteredLogger(String, long, long, TimeUnit)}
	 *             instead.
	 */
	@Deprecated
	public FilteredLogger(Logger logger, long maxPerPeriod, long period, TimeUnit unit) {
		this.logger = logger;
		this.maxPerPeriod = maxPerPeriod;
		this.nanosPerPeriod = unit.toNanos(period);
		this.startNanos = ClockUtil.nanoRealtime();
	}

	/**
	 * Create logging filter.
	 * 
	 * @param name name of logger to log
	 * @param maxPerPeriod maximum logging messages per period.
	 * @param nanosPerPeriod nanoseconds per period.
	 * @since 3.10
	 */
	public FilteredLogger(String name, long maxPerPeriod, long nanosPerPeriod) {
		this(name, maxPerPeriod, nanosPerPeriod, TimeUnit.NANOSECONDS);
	}

	/**
	 * Create logging filter.
	 * 
	 * @param name name of logger to log
	 * @param maxPerPeriod maximum logging messages per period.
	 * @param period period in units
	 * @param unit time unit of the period
	 * @since 3.10
	 */
	public FilteredLogger(String name, long maxPerPeriod, long period, TimeUnit unit) {
		this.logger = LoggerFactory.getLogger(name);
		this.maxPerPeriod = maxPerPeriod;
		this.nanosPerPeriod = unit.toNanos(period);
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
			log(Level.WARN, fmt, args);
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
			log(Level.INFO, fmt, args);
		}
	}

	/**
	 * Filter debug logging.
	 * 
	 * @param fmt format
	 * @param args arguments
	 */
	public void debug(String fmt, Object... args) {
		if (logger.isDebugEnabled()) {
			log(Level.DEBUG, fmt, args);
		}
	}

	/**
	 * Filter trace logging.
	 * 
	 * @param fmt format
	 * @param args arguments
	 */
	public void trace(String fmt, Object... args) {
		if (logger.isTraceEnabled()) {
			log(Level.TRACE, fmt, args);
		}
	}

	private void log(Level level, String fmt, Object... args) {
		boolean info;
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
						int length = args.length;
						args = Arrays.copyOf(args, length + 1);
						args[length] = counter;
						fmt += " ({} additional errors.)";
						info = true;
					}
					counter = 0;
				}
			}
		} else {
			info = true;
		}
		if (info) {
			switch (level) {
			case ERROR:
				logger.error(fmt, args);
				break;
			case WARN:
				logger.warn(fmt, args);
				break;
			case INFO:
				logger.info(fmt, args);
				break;
			case DEBUG:
				logger.debug(fmt, args);
				break;
			case TRACE:
				logger.trace(fmt, args);
				break;
			}
		}
	}
}
