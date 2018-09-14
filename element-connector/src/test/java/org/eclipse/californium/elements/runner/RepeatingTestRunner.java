/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix typo "alife" with "alive"
 *                                                    cleanup logging
 ******************************************************************************/
package org.eclipse.californium.elements.runner;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.runner.Description;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunListener;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;

/**
 * Runner for tests under debugging.
 * 
 * Runs a test repeated until it fails or the maximum number of repeats is
 * reached.
 * 
 * <pre>
 * "org.eclipse.californium.elements.runner.RepeatingTestRunner.repeats", maximum number of repeats for test.
 * 0 := repeat test until failure. Default 100.
 * "org.eclipse.californium.elements.runner.RepeatingTestRunner.alive", interval in milliseconds.
 * 0 := disabled. Default: 1000
 * </pre>
 * 
 * To use, add runner to JUni test with
 * 
 * <pre>
 * &#64;RunWith(RepeatingTestRunner.class)
 * public class SomeTests {
 * </pre>
 * 
 * For execution with maven {@code -Dtest="XyzAbcTest" -DfailIfNoTests=false} may be used.
 * 
 * Note: If used with "maven-surefire-plugin", parallel testing can not be used!
 */
public class RepeatingTestRunner extends BlockJUnit4ClassRunner {

	public static final Logger LOGGER = Logger.getLogger(RepeatingTestRunner.class.getName());

	/**
	 * Final divisor for logging memory in mega bytes.
	 */
	private static final int MEGA_BYTE = 1024 * 1024;
	/**
	 * Default maximum number of repeats. Current value 100.
	 * 
	 * @see #maximumRepeats
	 */
	private static final int DEFAULT_MAXIMUM_REPEATS = 100;
	/**
	 * Default interval for alive logging in milliseconds. Current value 1000.
	 */
	private static final int DEFAULT_ALIVE_INTERVAL_IN_MILLISECONDS = 1000;
	/**
	 * Maximum number of repeats.
	 * 
	 * 0 := repeat until failure. May be set via property
	 * "org.eclipse.californium.runner.RepeatingTestRunner.repeats". Default
	 * {@link #DEFAULT_MAXIMUM_REPEATS}.
	 */
	private final long maximumRepeats;
	/**
	 * Interval for alive logging in milliseconds.
	 * 
	 * 0 := disabled. May be set via property
	 * "org.eclipse.californium.runner.RepeatingTestRunner.alive". Default
	 * {@link #DEFAULT_ALIVE_INTERVAL_IN_MILLISECONDS}.
	 */
	private final int aliveIntervalInMilliseconds;

	public RepeatingTestRunner(Class<?> klass) throws InitializationError {
		super(klass);
		Integer value = getProperty(RepeatingTestRunner.class.getName() + ".repeats");
		maximumRepeats = null == value ? DEFAULT_MAXIMUM_REPEATS : value;
		value = getProperty(RepeatingTestRunner.class.getName() + ".alive");
		aliveIntervalInMilliseconds = null == value ? DEFAULT_ALIVE_INTERVAL_IN_MILLISECONDS : value;
	}

	/**
	 * Get integer value from property with provided name.
	 * 
	 * @param name name of property
	 * @return value, of {@code null}, if property is not defined or value is no
	 *         integer number.
	 */
	private Integer getProperty(String name) {
		String value = System.getProperty(name);
		if (null != value) {
			try {
				return Integer.valueOf(value);
			} catch (NumberFormatException ex) {
				LOGGER.log(Level.SEVERE, "value for ''{0}'' := ''{1}'' is no number!", new Object[] { name, value });
			}
		}
		return null;
	}

	@Override
	public void run(final RunNotifier notifier) {
		if (0 == maximumRepeats) {
			LOGGER.log(Level.CONFIG, "repeat until error!");
		} else {
			LOGGER.log(Level.CONFIG, "maximum repeats: {0}", maximumRepeats);
		}
		// start alive logging
		Thread alive = startAliveLogging();
		// setup failure detection
		final AtomicInteger loop = new AtomicInteger();
		final AtomicInteger failureCounter = new AtomicInteger();
		notifier.addListener(new RunListener() {

			@Override
			public void testStarted(Description description) throws Exception {
				logInfo("test", "[loop={0}] started {1}.", loop, description);
			}

			@Override
			public void testFinished(Description description) throws Exception {
				logInfo("test", "[loop={0}] finished {1}.", loop, description);
			}

			@Override
			public void testFailure(Failure failure) throws Exception {
				failureCounter.incrementAndGet();
			}

			public void testAssumptionFailure(Failure failure) {
				failureCounter.incrementAndGet();
			}

		});

		while ((loop.incrementAndGet() <= maximumRepeats) || (0 == maximumRepeats)) {
			logInfo("while", "[loop={0}] begin", loop);
			super.run(notifier);
			if (0 < failureCounter.get()) {
				logInfo("while", "[loop={0}] failed!", loop);
				break;
			}
			logInfo("while", "[loop={0}] ready", loop);
		}

		if (null != alive) {
			// try to stop alive logging
			try {
				alive.join(200);
			} catch (InterruptedException e) {
			}
		}
	}

	/**
	 * Write a logging with provided message and memory statistic.
	 * 
	 * @param format format for message to be logged
	 * @param parameters parameters to be formatted for logging
	 */
	private void logInfo(String tag, String format, Object... parameters) {
		if (LOGGER.isLoggable(Level.INFO)) {
			Runtime runtime = Runtime.getRuntime();
			LOGGER.log(Level.INFO, tag + ": " + format, parameters);
			LOGGER.log(Level.INFO, tag + ": memory free {0} MByte, total {1} MByte, max {2} MByte",
					new Object[] { runtime.freeMemory() / MEGA_BYTE, runtime.totalMemory() / MEGA_BYTE,
							runtime.maxMemory() / MEGA_BYTE });
		}
	}

	/**
	 * Start alive logging.
	 * 
	 * @return thread, or null, if alive logging is not started.
	 * @see #aliveIntervalInMilliseconds
	 */
	private Thread startAliveLogging() {
		Thread live = null;
		if (0 < aliveIntervalInMilliseconds && LOGGER.isLoggable(Level.INFO)) {
			LOGGER.log(Level.INFO, "start alife logging every {0}ms!", aliveIntervalInMilliseconds);
			live = new Thread(new Runnable() {

				@Override
				public void run() {
					try {
						int count = 0;
						long start = System.nanoTime();
						while (true) {
							Thread.sleep(aliveIntervalInMilliseconds);
							++count;
							long time = TimeUnit.NANOSECONDS.toMillis((System.nanoTime() - start) / count);
							logInfo("alive", "{0}. {1}ms", count, time);
						}
					} catch (InterruptedException e) {
					}
				}
			}, "live");
			live.setDaemon(true);
			live.start();
		}
		return live;
	}
}
