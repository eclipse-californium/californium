/*******************************************************************************
 * Copyright (c) 2022 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock.ReadLock;
import java.util.concurrent.locks.ReentrantReadWriteLock.WriteLock;

/**
 * A read-write-lock connection store.
 * 
 * @since 3.5
 */
public interface ReadWriteLockConnectionStore extends ResumptionSupportingConnectionStore {

	/**
	 * Shrinks the connection store.
	 * 
	 * @param calls number of calls
	 * @param running {@code true}, if the related connector is running,
	 *            {@code false}, if the connector has stopped and the shrinking
	 *            may be abandoned.
	 */
	void shrink(int calls, AtomicBoolean running);

	/**
	 * Set executor to pass to new connections.
	 * 
	 * @param executor executor to pass to new connections. May be {@code null}.
	 */
	void setExecutor(ExecutorService executor);

	/**
	 * Get read lock.
	 * 
	 * @return read lock
	 */
	ReadLock readLock();

	/**
	 * Get write lock.
	 * 
	 * @return write lock
	 */
	WriteLock writeLock();

}
