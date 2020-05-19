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
 *    Bosch Software Innovations - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.rule;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Threads rule for junit tests.
 * 
 * Ensure, that all new threads are terminated.
 */
public class ThreadsRule implements TestRule {

	public static final Logger LOGGER = LoggerFactory.getLogger(ThreadsRule.class);

	/**
	 * Description of current test.
	 */
	private volatile Description description;

	/**
	 * List of active threads on test start.
	 */
	private List<Thread> activeThreads;

	/**
	 * List with regex to exclude threads from termination check.
	 */
	private final String[] excludes;

	/**
	 * Create a threads rule.
	 * 
	 * @param excludes regex patterns to exclude threads by name from the
	 *            termination check
	 */
	public ThreadsRule(String... excludes) {
		this.excludes = excludes != null && excludes.length == 0 ? null : excludes;
	}

	@Override
	public String toString() {
		Description description = this.description;
		if (null == description) {
			return super.toString();
		} else if (description.isTest()) {
			return description.getDisplayName() + " (@Rule)";
		} else {
			return description.getDisplayName() + " (@ClassRule)";
		}
	}

	/**
	 * Start rule.
	 * 
	 * Save threads snapshot and calls {@link #initialize()}.
	 * 
	 * @throws IllegalStateException if the number of active threads is changing
	 *             too fast.
	 */
	private final void startRule(final Description description) {
		activeThreads = getActiveThreads();
		synchronized (this) {
			this.description = description;
		}
		initialize();
	}

	/**
	 * Close rule.
	 * 
	 * Calls {@link #shutdown()} and then verifies, that no new thread is still
	 * alive.
	 * 
	 * @param reportLeakAsException {@code true}, if leaks are reported with a
	 *            {@link IllegalStateException}, {@code false} to only write
	 *            logging.
	 * @throws IllegalStateException if the number of active threads is changing
	 *             too fast or new threads are still alive.
	 */
	private final void closeRule(boolean reportLeakAsException) {
		shutdown();
		checkThreadLeak(activeThreads, reportLeakAsException);
		synchronized (this) {
			this.description = null;
		}
	}

	/**
	 * Get list of active threads.
	 * 
	 * @return list of active threads
	 * @throws IllegalStateException if the number of active threads is changing
	 *             too fast.
	 */
	public List<Thread> getActiveThreads() {
		int loops = 10;
		int before = 0;
		int[] counts = new int[loops * 2];
		Thread[] active = null;
		for (int i = 0; i < loops; ++i) {
			int count = Thread.activeCount();
			counts[i * 2] = count;
			if (active == null || active.length < count + 1) {
				// one more to check for changes
				active = new Thread[count + 1];
			}
			Arrays.fill(active, null);
			int actual = Thread.enumerate(active);
			counts[(i * 2) + 1] = actual;
			if (actual == count || actual == before) {
				List<Thread> threads = new ArrayList<Thread>(actual);
				for (int index = 0; index < actual; ++index) {
					Thread thread = active[index];
					if (thread != null && thread.isAlive()) {
						boolean skip = false;
						if (excludes != null) {
							for (String pattern : excludes) {
								if (thread.getName().matches(pattern)) {
									skip = true;
									break;
								}
							}
						}
						if (!skip) {
							threads.add(thread);
						}
					}
				}
				return threads;
			} else {
				before = actual;
			}
		}
		throw new IllegalStateException("Active threads unstable! " + Arrays.toString(counts));
	}

	/**
	 * Check for thread leaks.
	 * 
	 * @param activeThreads list of active threads at
	 *            {@link #startRule(Description)}.
	 * @param reportLeakAsException {@code true}, if leaks are reported with a
	 *            {@link IllegalStateException}, {@code false} to only write
	 *            logging.
	 * @throws IllegalStateException if the number of active threads is changing
	 *             too fast or new threads are still alive.
	 */
	public void checkThreadLeak(List<Thread> activeThreads, boolean reportLeakAsException) {
		List<Thread> listAfter = getJoinedThreadList(activeThreads);
		if (!listAfter.isEmpty()) {
			listAfter = getJoinedThreadList(activeThreads);
			if (!listAfter.isEmpty()) {
				int alive = 0;
				for (Thread thread : listAfter) {
					if (thread.isAlive()) {
						++alive;
						LOGGER.warn("Thread {} is still alive!", thread.getName());
					}
				}
				if (alive > 0) {
					dump("leaking " + description, listAfter);
					if (reportLeakAsException) {
						throw new IllegalStateException(
								"Active threads differs by " + alive + "! (" + description + ")");
					}
				}
			}
		}
	}

	private List<Thread> getJoinedThreadList(List<Thread> activeThreads) {
		List<Thread> listAfter = getActiveThreads();
		listAfter.removeAll(activeThreads);
		if (!listAfter.isEmpty()) {
			for (Thread thread : listAfter) {
				try {
					thread.join(1000);
				} catch (InterruptedException e) {
					LOGGER.warn("Interrupted while joining Thread {}!", thread.getName());
				}
			}
		}
		return listAfter;
	}

	/**
	 * Dump list of threads.
	 * 
	 * @param message message to be logged in summary.
	 * @param list list of threads
	 */
	public void dump(String message, List<Thread> list) {
		LOGGER.info("Threads {}: {} threads", message, list.size());
		for (Thread thread : list) {
			if (thread != null) {
				ThreadGroup threadGroup = thread.getThreadGroup();
				String mark = "";
				if (thread.isInterrupted()) {
					if (thread.isAlive()) {
						mark = " interrupted alive";
					} else {
						mark = " interrupted died";
					}
				} else {
					if (thread.isAlive()) {
						mark = " alive";
					} else {
						mark = " died";
					}
				}
				if (threadGroup != null) {
					LOGGER.info("Threads {} : {}-{}{}", description, thread.getName(), threadGroup.getName(), mark);
				} else {
					LOGGER.info("Threads {} : {}{}", description, thread.getName(), mark);
				}
				if (LOGGER.isTraceEnabled()) {
					StackTraceElement[] stackTrace = thread.getStackTrace();
					for (StackTraceElement trace : stackTrace) {
						LOGGER.trace("   {}", trace);
					}
				}
			} else {
				LOGGER.error("Threads {} : active threads list corrupted!", description);
			}
		}
	}

	@Override
	public Statement apply(final Statement base, final Description description) {
		return new Statement() {

			@Override
			public void evaluate() throws Throwable {
				startRule(description);
				try {
					base.evaluate();
				} catch (Throwable t) {
					closeRule(false);
					throw t;
				}
				closeRule(true);
			}
		};
	}

	/**
	 * Initialize resources after threads snapshot was created.
	 */
	protected void initialize() {
	}

	/**
	 * Shutdown resources before threads are verified to be terminated.
	 */
	protected void shutdown() {
	}
}
