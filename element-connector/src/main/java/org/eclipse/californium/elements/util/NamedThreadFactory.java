/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The default thread factory.
 */
public class NamedThreadFactory implements ThreadFactory {

	/**
	 * The default thread group for Californium threads.
	 */
	public static final ThreadGroup COAP_THREAD_GROUP = new ThreadGroup("Californium"); //$NON-NLS-1$
	/**
	 * The default thread group for Scandium threads.
	 */
	public static final ThreadGroup SCANDIUM_THREAD_GROUP = new ThreadGroup("Scandium"); //$NON-NLS-1$
	/**
	 * The default thread group for transport threads.
	 * 
	 * @since 4.0
	 */
	public static final ThreadGroup TRANSPORT_THREAD_GROUP = new ThreadGroup("Transport"); //$NON-NLS-1$

	static {
		// reset daemon, may be set by parent group!
		COAP_THREAD_GROUP.setDaemon(false);
		SCANDIUM_THREAD_GROUP.setDaemon(false);
	}

	private final ThreadGroup group;
	private final AtomicLong index;
	private final String prefix;
	private final boolean daemon;

	/**
	 * Creates a new factory and sets the thread group to Californium default
	 * group.
	 *
	 * @param threadPrefix the prefix, that becomes part of the name of all
	 *            threads, created by this factory.
	 */
	public NamedThreadFactory(final String threadPrefix) {
		this(threadPrefix, null, false);
	}

	/**
	 * Creates a new factory.
	 *
	 * @param threadPrefix the prefix, that becomes part of the name of all
	 *            threads, created by this factory.
	 * @param threadGroup the thread group or {@code null}
	 */
	public NamedThreadFactory(final String threadPrefix, final ThreadGroup threadGroup) {
		this(threadPrefix, threadGroup, false);
	}

	/**
	 * Creates a new factory.
	 *
	 * @param threadPrefix the prefix, that becomes part of the name of all
	 *            threads, created by this factory.
	 * @param threadGroup the thread group or {@code null}
	 * @param daemon {@code true} to create daemon threads
	 * @since 4.0
	 */
	public NamedThreadFactory(final String threadPrefix, final ThreadGroup threadGroup, boolean daemon) {
		this(threadPrefix, threadGroup, daemon, 0L);
	}

	/**
	 * Creates a new factory.
	 *
	 * @param threadPrefix the prefix, that becomes part of the name of all
	 *            threads, created by this factory.
	 * @param threadGroup the thread group or {@code null}
	 * @param daemon {@code true} to create daemon threads
	 * @param start start value for name index
	 * @since 4.0
	 */
	public NamedThreadFactory(final String threadPrefix, final ThreadGroup threadGroup, boolean daemon, Long start) {
		prefix = threadPrefix;
		group = null == threadGroup ? COAP_THREAD_GROUP : threadGroup;
		this.daemon = daemon;
		if (start != null) {
			index = new AtomicLong(start);
		} else {
			index = null;
		}
	}

	/**
	 * Creates a new thread for executing a runnable.
	 * <p>
	 * The thread created will be a member of the thread group set during
	 * instantiation of this factory. The thread's priority will be set to
	 * {@link Thread#NORM_PRIORITY}.
	 * 
	 * @param runnable The runnable that should be executed by the created
	 *            thread.
	 * @return The newly created thread.
	 * @see #createDaemonThreads()
	 */
	@Override
	public final Thread newThread(Runnable runnable) {
		String name = prefix;
		if (index != null) {
			name += index.getAndIncrement();
		}
		final Thread ret = new Thread(group, runnable, name, 0);
		ret.setDaemon(createDaemonThreads());
		if (ret.getPriority() != Thread.NORM_PRIORITY) {
			ret.setPriority(Thread.NORM_PRIORITY);
		}
		return ret;
	}

	/**
	 * Checks whether this factory creates daemon threads.
	 * <p>
	 * This method is invoked by {@link #newThread(Runnable)} right after a new
	 * thread has been created. The {@link Thread#setDaemon(boolean)} method is
	 * invoked with this method's return value.
	 * 
	 * @return {@code true} if all threads created by this factory are daemon
	 *         threads. This implementation returns {@code false}. Subclasses
	 *         should override this method and return {@code true} in order to
	 *         create daemon threads.
	 */
	protected boolean createDaemonThreads() {
		return daemon;
	}

	/**
	 * Thread type of factory.
	 * 
	 * @since 4.0
	 */
	public enum Type {
		/**
		 * Normal thread.
		 */
		NORMAL,
		/**
		 * Daemon thread.
		 */
		DAEMON,
		/**
		 * Virtual thread, if supported by JVM. Otherwise daemon thread.
		 */
		VIRTUAL,
	}

	/**
	 * Create thread factory.
	 * <p>
	 * If virtual threads are requested, but not supported by the JVM, a daemon
	 * thread factory is returned instead.
	 * 
	 * @param prefix prefix for thread names
	 * @param start starting number for thread names. May be {@code null} to not
	 *            append numbers.
	 * @param group thread group. Not used for virtual threads
	 * @param type type of thread.
	 * @return thread factory
	 * @since 4.0
	 */
	public static ThreadFactory create(String prefix, Long start, ThreadGroup group, Type type) {
		if (start != null) {
			prefix += "-";
		}
		switch (type) {
		default:
		case NORMAL:
			return new NamedThreadFactory(prefix, group, false, start);
		case DAEMON:
			return new NamedThreadFactory(prefix, group, true, start);
		case VIRTUAL:
			if (VirtualThreadFactory.isAvailable()) {
				return VirtualThreadFactory.create(prefix, start);
			} else {
				return new NamedThreadFactory(prefix, group, true, start);
			}
		}
	}
}
