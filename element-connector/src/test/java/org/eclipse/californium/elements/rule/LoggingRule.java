/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.rule;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Logging rule for junit tests.
 * 
 * Alter the logging level during unit tests to reduce amount of logging.
 * Intended to be used for unit tests, which causing logging messages by the
 * intention of the test. Implemented using reflection and supports currently
 * only logback.
 * 
 * @since 3.0
 */
public class LoggingRule implements TestRule {

	private static final Class<?> LOGGER_CLASS;
	private static final Method SET_LEVEL;
	private static final Method GET_LEVEL;
	private static final Method TO_LEVEL;

	static {
		Class<?> loggerClass = null;
		Method setLevel = null;
		Method getLevel = null;
		Class<?> levelClass = null;
		Method toLevel = null;
		try {
			loggerClass = Class.forName("ch.qos.logback.classic.Logger");
			levelClass = Class.forName("ch.qos.logback.classic.Level");
			setLevel = loggerClass.getMethod("setLevel", levelClass);
			getLevel = loggerClass.getMethod("getLevel");
			toLevel = levelClass.getMethod("toLevel", String.class);
		} catch (Throwable t) {
			loggerClass = null;
			setLevel = null;
			getLevel = null;
			toLevel = null;
		}
		LOGGER_CLASS = loggerClass;
		SET_LEVEL = setLevel;
		GET_LEVEL = getLevel;
		TO_LEVEL = toLevel;
	}

	/**
	 * Description of current test.
	 */
	private volatile Description description;

	/**
	 * Array with altered logger.
	 */
	private volatile Logger[] logbackLoggers;
	/**
	 * Backup levels to restore levels afterwards
	 */
	private volatile Object[] backupLevels;

	/**
	 * Create logging rule.
	 */
	public LoggingRule() {
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

	private void startRule(Description description) {
		this.description = description;
	}

	/**
	 * Set logging level fort scope of this rule.
	 * 
	 * MUST be called only once per test!
	 * 
	 * @param levelname name of level, "ERROR", "WARN", "INFO", "DEBUG, or
	 *            "TRACE".
	 * @param loggerNames names of loggers.
	 */
	public LoggingRule setLoggingLevel(String levelname, String... loggerNames) {
		if (LOGGER_CLASS == null) {
			// no logback implementation available
			return this;
		}
		if (logbackLoggers != null) {
			throw new IllegalStateException("Logging level already applied!");
		}
		Logger[] loggers = new Logger[loggerNames.length];
		for (int index = 0; index < loggerNames.length; ++index) {
			loggers[index] = LoggerFactory.getLogger(loggerNames[index]);
		}
		return setLoggingLevel(levelname, loggers);
	}

	/**
	 * Set logging level fort scope of this rule.
	 * 
	 * MUST be called only once per test!
	 * 
	 * @param levelname name of level, "ERROR", "WARN", "INFO", "DEBUG, or
	 *            "TRACE".
	 * @param loggerClasses classes of loggers.
	 */
	public LoggingRule setLoggingLevel(String levelname, Class<?>... loggerClasses) {
		if (LOGGER_CLASS == null) {
			// no logback implementation available
			return this;
		}
		if (logbackLoggers != null) {
			throw new IllegalStateException("Logging level already applied!");
		}
		Logger[] loggers = new Logger[loggerClasses.length];
		for (int index = 0; index < loggerClasses.length; ++index) {
			loggers[index] = LoggerFactory.getLogger(loggerClasses[index]);
		}
		return setLoggingLevel(levelname, loggers);
	}

	/**
	 * Set logging level fort scope of this rule.
	 * 
	 * MUST be called only once per test!
	 * 
	 * @param levelname name of level, "ERROR", "WARN", "INFO", "DEBUG, or
	 *            "TRACE".
	 * @param loggers loggers.
	 */
	public LoggingRule setLoggingLevel(String levelname, Logger... loggers) {
		if (LOGGER_CLASS == null) {
			// no logback implementation available
			return this;
		}
		if (this.logbackLoggers != null) {
			throw new IllegalStateException("Logging level already applied!");
		}
		try {
			Object level = TO_LEVEL.invoke(null, levelname);
			logbackLoggers = new Logger[loggers.length];
			backupLevels = new Object[loggers.length];
			for (int index = 0; index < loggers.length; ++index) {
				if (LOGGER_CLASS.isInstance(loggers[index])) {
					logbackLoggers[index] = loggers[index];
					backupLevels[index] = GET_LEVEL.invoke(loggers[index]);
					SET_LEVEL.invoke(loggers[index], level);
				}
			}
		} catch (IllegalAccessException e) {
		} catch (IllegalArgumentException e) {
		} catch (InvocationTargetException e) {
		}
		return this;
	}

	private void closeRule() {
		if (logbackLoggers != null) {
			try {
				for (int index = 0; index < logbackLoggers.length; ++index) {
					Object level = backupLevels[index];
					SET_LEVEL.invoke(logbackLoggers[index], level);
				}
			} catch (IllegalAccessException e) {
			} catch (IllegalArgumentException e) {
			} catch (InvocationTargetException e) {
			}
			logbackLoggers = null;
			backupLevels = null;
		}
		description = null;
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
					closeRule();
					throw t;
				}
				closeRule();
			}
		};
	}
}
