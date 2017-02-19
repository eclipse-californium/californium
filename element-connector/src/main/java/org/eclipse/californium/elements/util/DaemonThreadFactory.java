package org.eclipse.californium.elements.util;

/**
 * A factory to create executor services with daemon threads.
 */
public class DaemonThreadFactory extends NamedThreadFactory {

	/**
	 * Creates a new factory and sets the thread group to Californium
	 * default group.
	 *
	 * @param threadPrefix the prefix, that becomes part of the name of all
	 *            threads, created by this factory.
	 */
	public DaemonThreadFactory(final String threadPrefix) {
		super(threadPrefix, null);
	}

	/**
	 * Creates a new factory.
	 *
	 * @param threadPrefix the prefix, that becomes part of the name of all
	 *            threads, created by this factory.
	 * @param threadGroup the thread group or <code>null</code>
	 */
	public DaemonThreadFactory(final String threadPrefix, final ThreadGroup threadGroup) {
		super(threadPrefix, threadGroup);
	}

	@Override
	protected boolean createDaemonThreads() {
		return false;
	}
}
