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
 ******************************************************************************/
package org.eclipse.californium.elements.rule;

import java.io.IOError;
import java.net.DatagramSocket;
import java.net.DatagramSocketImpl;
import java.net.SocketException;
import java.util.Deque;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.elements.category.NativeDatagramSocketImplRequired;
import org.eclipse.californium.elements.util.DatagramFormatter;
import org.eclipse.californium.elements.util.DirectDatagramSocketImpl;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

/**
 * Network rule for datagram junit tests.
 * 
 * Defines, if the test should be execute with native datagram sockets (NATIVE),
 * and/or direct datagram sockets using "in process" messaging (DIRECT). The
 * supported modes of the test are provided as parameter of the constructor. If
 * DIRECT is supported, additional parameter may also be used.
 * 
 * Though the {@link DatagramSocket#setDatagramSocketImplFactory} could only be
 * called once, all executed tests must use the same DatagramSocketImpl.
 * Therefore this rule doesn't setup the DatagramSocketImpl, it just filters the
 * test according the supported modes. For usage within maven, a category
 * {@link NativeDatagramSocketImplRequired} is also available.
 * 
 * The used socket mode is setup on the first usage, according the definition of
 * the property "org.eclipse.californium.junit.socketmode". The value must be
 * either "NATIVE" or "DIRECT". When tests are executed, it's checked, if the
 * test supports the used mode, and, if not the test is skipped. For executing
 * the junit test within eclipse, you may provide the mode either at
 * project/runner level as VM arguments, or general for a JRE as default VM
 * arguments (Window->Preferences | Java -> Installed JREs | select and EDIT).
 * 
 * The intended use within maven is therefore to use the introduced category
 * {@link NativeDatagramSocketImplRequired} to select the tests running DIRECT
 * and run the NATIVE test in a separate execution.
 * 
 * The intended use within eclipse is setup two configurations, one for DIRECT
 * using "-Dorg.eclipse.californium.junit.socketmode=DIRECT", and one for NATIVE
 * using "-Dorg.eclipse.californium.junit.socketmode=NATIVE". Currently the
 * default is NATIVE. I hope, after a introduction period, it could be changed
 * to DIRECT.
 * 
 * If the rule scope is left, the rule checks for left open DatagramSockets.
 * Therefore it's important to chose the right scope for the rule. The
 * <code>&#64;ClassRule<code> is required for tests, which starts a server once
 * and then reuse it on several tests. <code>&#64;Rule<code> could be used, if
 * every test cleans up on its own.
 * 
 * <pre>
 * public class AbcNetworkTest {
 *    &#64;ClassRule
 *    public static NetworkRule network = new NetworkRule(Mode.DIRECT, Mode.NATIVE);
 * 
 * </pre>
 * 
 */
public class NetworkRule implements TestRule {

	public static final Logger LOGGER = Logger.getLogger(NetworkRule.class.getName());
	/**
	 * Name of configuration property. Supported values of property "NATIVE" and
	 * "DIRECT".
	 */
	public static final String PROPERTY_NAME = "org.eclipse.californium.junit.socketmode";

	/**
	 * Default datagram formatter.
	 */
	private static final DatagramFormatter DEFAULT_FORMATTER = null;
	/**
	 * Default message processing delay.
	 */
	private static final int DEFAULT_DELAY_IN_MILLIS = 0;

	/**
	 * Used datagram socket implementation mode.
	 */
	private static final Mode usedMode;
	/**
	 * Stack of rules. Support class rules and nested method rules.
	 */
	private static final Deque<NetworkRule> RULES_STACK = new LinkedList<NetworkRule>();

	static {
		Mode mode = Mode.NATIVE;
		String envMode = System.getProperty(PROPERTY_NAME);
		if (null != envMode) {
			try {
				mode = Mode.valueOf(envMode);
			} catch (IllegalArgumentException ex) {
				LOGGER.log(Level.SEVERE, "Value {0} for property {1} not supported!",
						new Object[] { envMode, PROPERTY_NAME });
			}
		}
		usedMode = mode;
		if (Mode.DIRECT == usedMode) {
			DirectDatagramSocketImpl.initialize(new DirectDatagramSocketImpl.DirectDatagramSocketImplFactory() {

				@Override
				public DatagramSocketImpl createDatagramSocketImpl() {
					if (!isActive()) {
						String message = "Use " + NetworkRule.class.getName() + " to define DatagramSocket behaviour!";
						LOGGER.log(Level.SEVERE, message);
						/*
						 * check, if datagram socket is created in the scope of
						 * a NetworkRule.
						 */
						throw new IOError(new SocketException(message));
					}
					return super.createDatagramSocketImpl();
				}
			});
		}
	}

	/**
	 * Statement to skip test. Used to filter test which not supports the
	 * {@link #usedMode}.
	 */
	private static final Statement SKIP = new Statement() {

		@Override
		public void evaluate() throws Throwable {
			/* skip, do nothing */
		}
	};

	/**
	 * DatagramSocketImpl modes.
	 */
	public enum Mode {
		/**
		 * Native datagram socket implementation (using operation system).
		 */
		NATIVE,
		/**
		 * Direct datagram socket implementation.
		 * 
		 * @see DirectDatagramSocketImpl
		 */
		DIRECT
	}

	/**
	 * Array of supported modes.
	 */
	private final Mode[] supportedModes;

	/**
	 * Datagram formatter to be used.
	 * 
	 * @see #DEFAULT_FORMATTER
	 */
	private final DatagramFormatter formatter;
	/**
	 * Delay for message processing.
	 * 
	 * @see #DEFAULT_DELAY_IN_MILLIS
	 */
	private int delayInMillis;

	/**
	 * Description of current test.
	 */
	private Description description;

	/**
	 * Create rule supporting provided modes.
	 * 
	 * @param modes supported datagram socket implementation modes.
	 */
	public NetworkRule(Mode... modes) {
		this(DEFAULT_FORMATTER, modes);
	}

	/**
	 * Create rule supporting provided modes and formatter.
	 * 
	 * @param formatter datagram formatter to be used
	 * @param modes supported datagram socket implementation modes.
	 */
	protected NetworkRule(DatagramFormatter formatter, Mode... modes) {
		this.supportedModes = modes;
		this.formatter = formatter;
		this.delayInMillis = DEFAULT_DELAY_IN_MILLIS;
	}

	@Override
	public String toString() {
		Description description;
		synchronized (RULES_STACK) {
			description = this.description;
		}
		if (null == description) {
			return super.toString();
		} else if (description.isTest()) {
			return description.getDisplayName() + " (@Rule)";
		} else {
			return description.getDisplayName() + " (@ClassRule)";
		}
	}

	/**
	 * Check, if provided mode is in {@link #supportedModes}.
	 * 
	 * @param mode mode to check
	 * @return true, if provided mode is supported, false, otherwise
	 */
	private boolean supports(final Mode mode) {
		for (Mode supportedMode : supportedModes) {
			if (mode == supportedMode) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Set delay for processing messages.
	 * 
	 * Only used in DIRECT mode.
	 * 
	 * @param delayInMillis delay in milliseconds
	 * @return this rule
	 * @throws IllegalArgumentException, if the value is smaller then 0 or
	 *             DIRECT is not within the supported modes.
	 */
	public NetworkRule setDelay(int delayInMillis) {
		if (0 > delayInMillis) {
			throw new IllegalArgumentException("delays must be at least 0, not " + delayInMillis + "!");
		}
		if (!supports(Mode.DIRECT)) {
			throw new IllegalArgumentException("delays could only be used for DIRECT DatagramSockets!");
		}
		this.delayInMillis = delayInMillis;
		return this;
	}

	/**
	 * Apply configuration of rule.
	 * 
	 * Handles nesting of rules pushing rule to stack and setup configuration
	 * calling {@link #initNetwork(boolean)}.
	 */
	private final void applyConfig(final Description description) {
		int size;
		boolean first;
		synchronized (RULES_STACK) {
			this.description = description;
			first = RULES_STACK.isEmpty();
			RULES_STACK.push(this);
			size = RULES_STACK.size();
		}
		LOGGER.log(Level.INFO, "{0} rules active.", size);
		initNetwork(first);
	}

	/**
	 * Close configuration of rule.
	 * 
	 * Handles nesting of rules by removing the top rule from the stack and
	 * setup configuration of the next rule calling
	 * {@link #initNetwork(boolean)}, when available. When the last rule is
	 * removed from stack and no next rule is available, calls
	 * {@link #closeNetwork()}.
	 */
	private final void closeConfig() {
		int size;
		NetworkRule closedRule;
		NetworkRule activeRule;
		synchronized (RULES_STACK) {
			closedRule = RULES_STACK.pop();
			activeRule = RULES_STACK.peek();
			size = RULES_STACK.size();
		}
		LOGGER.log(Level.INFO, "{0} rules active.", size);
		if (this != closedRule) {
			throw new IllegalStateException("closed rule differs!");
		}
		if (null == activeRule) {
			closeNetwork();
		} else {
			activeRule.initNetwork(false);
		}
	}

	@Override
	public Statement apply(final Statement base, final Description description) {
		if (supports(usedMode)) {
			return new Statement() {

				@Override
				public void evaluate() throws Throwable {
					applyConfig(description);
					try {
						base.evaluate();
					} finally {
						closeConfig();
					}
				}
			};
		} else {
			LOGGER.log(Level.WARNING, "Skip {0} not applicable with socket mode {1}",
					new Object[] { description, usedMode });
			return SKIP;
		}
	}

	/**
	 * Initialize network for testing.
	 * 
	 * Configure network using
	 * {@link DirectDatagramSocketImpl#configure(DatagramFormatter, int)}, if
	 * {@link #usedMode} is {@link Mode#DIRECT}.
	 * 
	 * @param outerScope true, if called from the outer most rule. Usually the
	 *            rule is used as class rule and my use nested method rules. If
	 *            that's the case, outerScope is true for the class rule and
	 *            false for the method rule. If only method rules are used, it's
	 *            always true. If true, all open DIRECT sockets are cleaned up
	 *            and warnings are logged. This indicator is introduced to cover
	 *            situations, where the class setup starts a server, which is
	 *            then reused by several tests.
	 */
	protected void initNetwork(boolean outerScope) {
		if (Mode.DIRECT == usedMode) {
			if (outerScope && !DirectDatagramSocketImpl.isEmpty()) {
				LOGGER.info("Previous test did not call ''closeNetwork()''!");
				DirectDatagramSocketImpl.clearAll();
			}
			DirectDatagramSocketImpl.configure(formatter, delayInMillis);
		}
	}

	/**
	 * Close network after testing.
	 * 
	 * Ensure, that all sockets are closed. Reset network configuration to their
	 * defaults.
	 * 
	 * @see #DEFAULT_FORMATTER
	 * @see #DEFAULT_DELAY_IN_MILLIS
	 */
	protected void closeNetwork() {
		if (Mode.DIRECT == usedMode) {
			if (!DirectDatagramSocketImpl.isEmpty()) {
				Description description;
				synchronized (RULES_STACK) {
					description = this.description;
				}
				LOGGER.log(Level.INFO, "Test {0} did not close all DatagramSockets!", description);
				DirectDatagramSocketImpl.clearAll();
			}
			DirectDatagramSocketImpl.configure(DEFAULT_FORMATTER, DEFAULT_DELAY_IN_MILLIS);
		}
	}

	/**
	 * Ensure, that this rule is the currently active rule.
	 * 
	 * @throws IllegalStateException, if this rule is not currently active.
	 */
	protected void ensureThisRuleIsActive() throws IllegalStateException {
		NetworkRule activeRule;
		synchronized (RULES_STACK) {
			activeRule = RULES_STACK.peek();
		}
		if (this != activeRule) {
			Description description;
			synchronized (RULES_STACK) {
				description = this.description;
			}
			String message;

			if (null == description) {
				message = this + " rule is not applied!";
			} else {
				message = this + " rule is not active!";
			}
			if (null == activeRule) {
				message += " No active rule!";
			} else {
				message += " Instead " + activeRule + " is active!";

			}
			LOGGER.log(Level.SEVERE, message);
			throw new IllegalStateException(message);
		}
	}

	/**
	 * Check, is a network rule is active.
	 * 
	 * used to determine, if all DIRECT sockets are created within the scope of
	 * a {@link NetworkRule}.
	 * 
	 * @return true, if a network rule is active, false, otherwise.
	 */
	public static boolean isActive() {
		int size;
		boolean active;
		synchronized (RULES_STACK) {
			size = RULES_STACK.size();
			active = !RULES_STACK.isEmpty();
		}
		LOGGER.log(Level.INFO, "{0} rules active.", size);
		return active;
	}
}
