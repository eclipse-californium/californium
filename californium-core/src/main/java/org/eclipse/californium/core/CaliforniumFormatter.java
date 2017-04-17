/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - logging improvements
 *    Achim Kraus (Bosch Software Innovations GmbH) - move time to begin of line
 *                                                    use append for each
 *                                                    stacktrace line
 *    Achim Kraus (Bosch Software Innovations GmbH) - search for line number of caller
 ******************************************************************************/
package org.eclipse.californium.core;

import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Formatter;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;

/**
 * A JDK Logging Formatter that produces Californium specific log statements.
 * 
 * This formatter can be configured by means of a standard JDK logging
 * configuration file (see <a href=
 * "http://docs.oracle.com/javase/6/docs/api/java/util/logging/package-summary.html"
 * >java.util.logging</a> JavaDocs and in particular the LogManager and Handler
 * class documentation for details on how to do this).
 */
public class CaliforniumFormatter extends Formatter {

	private final LogPolicy logPolicy;

	/**
	 * Initializes the log policy with default values.
	 */
	public CaliforniumFormatter() {
		logPolicy = new LogPolicy();
	}

	/**
	 * Get line number of log call.
	 * 
	 * @param className class name of call
	 * @param methodName method name of call
	 * @return line number of log call, or {@code -1}, if caller could not be
	 *         determined.
	 */
	public int getCallersLineNumber(final String className, final String methodName) {
		// check for valid parameters
		if (null == className || null == methodName) {
			return -1;
		}

		StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();

		for (StackTraceElement element : stackTrace) {
			if (className.equals(element.getClassName()) && methodName.equals(element.getMethodName())) {
				return element.getLineNumber();
			}
		}

		return -1;
	}

	@Override
	public String format(final LogRecord record) {
		StringBuilder builder = new StringBuilder();
		if (logPolicy.dateFormat != null) {
			builder.append(logPolicy.dateFormat.format(new Date(record.getMillis()))).append(": ");
		}
		if (logPolicy.isEnabled(LogPolicy.LOG_POLICY_SHOW_THREAD_ID)) {
			builder.append(String.format("%3d", record.getThreadID())).append(" ");
		}
		if (logPolicy.isEnabled(LogPolicy.LOG_POLICY_SHOW_LEVEL)) {
			builder.append(record.getLevel().toString()).append(" ");
		}
		if (logPolicy.isEnabled(LogPolicy.LOG_POLICY_SHOW_CLASS)) {
			builder.append("[").append(getSimpleClassName(record.getSourceClassName())).append("]: ");
		}
		if (logPolicy.isEnabled(LogPolicy.LOG_POLICY_SHOW_MESSAGE)) {
			builder.append(formatMessage(record)).append(" - ");
		}
		if (logPolicy.isEnabled(LogPolicy.LOG_POLICY_SHOW_SOURCE)) {
			int lineNo = getCallersLineNumber(record.getSourceClassName(), record.getSourceMethodName());
			builder.append("(").append(record.getSourceClassName()).append(".java:").append(lineNo).append(") ");
		}
		if (logPolicy.isEnabled(LogPolicy.LOG_POLICY_SHOW_METHOD)) {
			builder.append(record.getSourceMethodName()).append("() ");
		}
		if (logPolicy.isEnabled(LogPolicy.LOG_POLICY_SHOW_THREAD)) {
			builder.append("in thread ").append(Thread.currentThread().getName());
		}
		builder.append(System.lineSeparator());
		append(builder, record.getThrown());
		return builder.toString();
	}

	/**
	 * Append stack trace of throwable to string builder.
	 * 
	 * @param builder string builder to append
	 * @param throwable throwable, may be {@code null}.
	 */
	private static void append(final StringBuilder builder, final Throwable throwable) {
		Throwable cause = throwable;
		while (null != cause) {
			builder.append(cause).append(System.lineSeparator());
			StackTraceElement[] stackTrace = cause.getStackTrace();
			for (StackTraceElement element : stackTrace) {
				builder.append("\tat ").append(element.getClassName()).append(".").append(element.getMethodName());
				if (element.isNativeMethod()) {
					builder.append("(Native Method)");
				}
				String filename = element.getFileName();
				if (null == filename) {
					builder.append("(Unknown Source)");
				} else {
					builder.append("(").append(filename);
					int line = element.getLineNumber();
					if (0 <= line) {
						builder.append(":").append(line);
					}
					builder.append(")");
				}
				builder.append(System.lineSeparator());
			}
			cause = cause.getCause();
			if (null != cause) {
				builder.append("caused by ");
			}
		}
	}

	/**
	 * Gets the simple class name.
	 *
	 * @param absolute the absolute class name
	 * @return the simple class name
	 */
	private static String getSimpleClassName(final String absolute) {
		String[] parts = absolute.split("\\.");
		return parts[parts.length - 1];
	}

	/**
	 * A set of boolean properties controlling the content of the log statement
	 * returned by {@link CaliforniumFormatter#format(LogRecord)}.
	 */
	private static class LogPolicy {

		private static final String LOG_POLICY_SHOW_CLASS = "californium.LogPolicy.showClass";
		private static final String LOG_POLICY_SHOW_LEVEL = "californium.LogPolicy.showLevel";
		private static final String LOG_POLICY_SHOW_METHOD = "californium.LogPolicy.showMethod";
		private static final String LOG_POLICY_SHOW_MESSAGE = "californium.LogPolicy.showMessage";
		private static final String LOG_POLICY_SHOW_SOURCE = "californium.LogPolicy.showSource";
		private static final String LOG_POLICY_SHOW_THREAD = "californium.LogPolicy.showThread";
		private static final String LOG_POLICY_SHOW_THREAD_ID = "californium.LogPolicy.showThreadID";
		private static final String LOG_POLICY_DATE_FORMAT = "californium.LogPolicy.dateFormat";

		private Map<String, Boolean> policy = new HashMap<String, Boolean>();
		private Format dateFormat = null;

		/**
		 * Instantiates a new log policy.
		 */
		private LogPolicy() {

			addPolicy(LOG_POLICY_SHOW_CLASS, Boolean.TRUE);
			addPolicy(LOG_POLICY_SHOW_LEVEL, Boolean.TRUE);
			addPolicy(LOG_POLICY_SHOW_CLASS, Boolean.TRUE);
			addPolicy(LOG_POLICY_SHOW_MESSAGE, Boolean.TRUE);
			addPolicy(LOG_POLICY_SHOW_METHOD, Boolean.TRUE);
			addPolicy(LOG_POLICY_SHOW_SOURCE, Boolean.TRUE);
			addPolicy(LOG_POLICY_SHOW_THREAD, Boolean.TRUE);
			addPolicy(LOG_POLICY_SHOW_THREAD_ID, Boolean.TRUE);

			// initialize date format from property specified in JDK logging
			// configuration
			String df = LogManager.getLogManager().getProperty(LOG_POLICY_DATE_FORMAT);
			if (df != null) {
				if (df.isEmpty()) {
					// date format configured as "" => disable date in output
				} else {
					dateFormat = new SimpleDateFormat(df);
				}
			} else {
				dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			}
		}

		/**
		 * Adds a particular configuration property for controlling content to
		 * be included in the formatter's output.
		 * 
		 * @param propertyName the name of the property to add to the policy
		 * @param defaultValue the value to fall back to if the
		 *            {@link LogManager} does not contain a value for the
		 *            configuration property
		 * @return the updated policy
		 */
		private LogPolicy addPolicy(final String propertyName, final boolean defaultValue) {
			String flag = LogManager.getLogManager().getProperty(propertyName);
			if (flag != null) {
				policy.put(propertyName, Boolean.parseBoolean(flag));
			} else {
				policy.put(propertyName, defaultValue);
			}
			return this;
		}

		private boolean isEnabled(final String propertyName) {
			Boolean result = policy.get(propertyName);
			return result != null ? result : false;
		}
	}
}
