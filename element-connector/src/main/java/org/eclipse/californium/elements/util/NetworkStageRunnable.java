/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.util.concurrent.ThreadFactory;
import java.util.function.BooleanSupplier;

import org.eclipse.californium.elements.Connector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Network stage runnable.
 * <p>
 * Execute network stage tasks. To support virtual threads, only short task are
 * intended. May get blocked by waiting on data.
 * 
 * @since 4.0
 */
public abstract class NetworkStageRunnable implements Runnable {

	/**
	 * The logger.
	 */
	private final Logger LOGGER;

	/**
	 * Forward {@link Connector#isRunning()} to network stage.
	 */
	private final BooleanSupplier running;

	/**
	 * Name.
	 * <p>
	 * Set to thread name by {@link #attach(ThreadFactory, boolean)}.
	 */
	private volatile String name;

	/**
	 * Creates network stage runnable.
	 * 
	 * @param running forward {@link Connector#isRunning()} to network stage
	 * @param logger clz for logger.
	 */
	public NetworkStageRunnable(BooleanSupplier running, Class<?> logger) {
		this.LOGGER = LoggerFactory.getLogger(logger);
		this.running = running;
	}

	/**
	 * Sets name.
	 * 
	 * @param name name of network stage runnable
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * Gets name.
	 * 
	 * @return name of network stage runnable
	 */
	public String getName() {
		return name;
	}

	@Override
	public void run() {
		try {
			LOGGER.info("Network stage thread [{}] started", getName());
			while (running.getAsBoolean()) {
				try {
					work();
				} catch (SocketTimeoutException e) {
					LOGGER.trace("Network stage thread [{}] socket timeout", getName(), e);
				} catch (InterruptedIOException e) {
					if (running.getAsBoolean()) {
						LOGGER.info("Network stage thread [{}] I/O has been interrupted", getName());
					} else {
						LOGGER.debug("Network stage thread [{}] I/O has been interrupted", getName());
					}
				} catch (InterruptedException e) {
					if (running.getAsBoolean()) {
						LOGGER.info("Network stage thread [{}] has been interrupted", getName());
					} else {
						LOGGER.debug("Network stage thread [{}] has been interrupted", getName());
					}
				} catch (Exception e) {
					if (running.getAsBoolean()) {
						LOGGER.debug("Exception thrown by Network stage thread [{}]", getName(), e);
					} else {
						LOGGER.trace("Exception thrown by Network stage thread [{}]", getName(), e);
					}
				}
			}
		} finally {
			if (running.getAsBoolean()) {
				LOGGER.info("Network stage thread [{}] has terminated", getName());
			} else {
				LOGGER.debug("Network stage thread [{}] has terminated", getName());
			}
		}
	}

	/**
	 * Repeated call to execute network stage work.
	 * <p>
	 * To support virtual threads, only short task are intended. May get blocked
	 * by waiting on data.
	 * 
	 * @throws Exception the exception to be properly logged
	 */
	protected abstract void work() throws Exception;

	/**
	 * Attach thread to network stage worker.
	 * 
	 * @param factory thread factory
	 * @param start start thread
	 * @return started thread.
	 */
	public Thread attach(ThreadFactory factory, boolean start) {
		Thread thread = factory.newThread(this);
		setName(thread.getName());
		if (start) {
			thread.start();
		}
		return thread;
	}
}
