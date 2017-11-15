package org.eclipse.californium.elements.util;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The default thread factory
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

	private final ThreadGroup group;
	private final AtomicInteger index = new AtomicInteger(1);
	private final String prefix;

	/**
	 * Creates a new factory and sets the thread group to Californium
	 * default group.
	 *
	 * @param threadPrefix the prefix, that becomes part of the name of all
	 *            threads, created by this factory.
	 */
	public NamedThreadFactory(final String threadPrefix) {
		this(threadPrefix, null);
	}

	/**
	 * Creates a new factory.
	 *
	 * @param threadPrefix the prefix, that becomes part of the name of all
	 *            threads, created by this factory.
	 * @param threadGroup the thread group or <code>null</code>
	 */
	public NamedThreadFactory(final String threadPrefix, final ThreadGroup threadGroup) {
		group = null == threadGroup ? COAP_THREAD_GROUP : threadGroup;
		prefix = threadPrefix;
	}

	/**
	 * Creates a new thread for executing a runnable.
	 * <p>
	 * The thread created will be a member of the thread group set during instantiation of this
	 * factory. The thread's priority will be set to {@link Thread#NORM_PRIORITY}.
	 * 
	 * @param runnable The runnable that should be executed by the created thread.
	 * @return The newly created thread.
	 * @see #createDaemonThreads()
	 */
	@Override
	public final Thread newThread(Runnable runnable) {
		final Thread ret = new Thread(group, runnable, prefix + index.getAndIncrement(), 0);
		ret.setDaemon(createDaemonThreads());
		if (ret.getPriority() != Thread.NORM_PRIORITY) {
			ret.setPriority(Thread.NORM_PRIORITY);
		}
		return ret;
	}

	/**
	 * Checks whether this factory creates daemon threads.
	 * <p>
	 * This method is invoked by {@link #newThread(Runnable)} right after a new thread has
	 * been created. The {@link Thread#setDaemon(boolean)} method is invoked with this method's
	 * return value.
	 * 
	 * @return {@code true} if all threads created by this factory are daemon threads. This implementation
	 *         returns {@code false}. Subclasses should override this method and return {@code true} in order
	 *         to create daemon threads.
	 */
	protected boolean createDaemonThreads() {
		return false;
	}
}
