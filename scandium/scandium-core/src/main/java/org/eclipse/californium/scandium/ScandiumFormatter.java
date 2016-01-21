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
 *    Stefan Jucker - DTLS implementation
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Formatter;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;

/**
 * A JDK Logging Formatter that produces Scandium specific log statements.
 * 
 * This formatter can be configured by means of a standard JDK logging
 * configuration file (see <a href=
 * "http://docs.oracle.com/javase/6/docs/api/java/util/logging/package-summary.html"
 * >java.util.logging</a> JavaDocs and in particular the LogManager and Handler
 * class documentation for details on how to do this).
 */
public class ScandiumFormatter extends Formatter {

	private LogPolicy logPolicy;
	
	/**
	 * Initializes the log policy with default values.
	 */
	public ScandiumFormatter() {
		logPolicy = new LogPolicy();
	}
	
	@Override
	public String format(LogRecord record) {

		String stackTrace = "";
    	Throwable throwable = record.getThrown();
    	if (throwable != null) {
    		StringWriter sw = new StringWriter();
    		throwable.printStackTrace(new PrintWriter(sw));
    		stackTrace = sw.toString();
    	}
    	
    	int lineNo;
    	StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    	if (throwable != null && stack.length > 7)
    		lineNo = stack[7].getLineNumber();
    	else if (stack.length > 8)
    		lineNo = stack[8].getLineNumber();
    	else lineNo = -1;
    	
    	StringBuffer b = new StringBuffer();
    	if (logPolicy.isEnabled(LogPolicy.LOG_POLICY_SHOW_THREAD_ID)) {
			b.append(String.format("%2d", record.getThreadID())).append(" ");
		}
		if (logPolicy.isEnabled(LogPolicy.LOG_POLICY_SHOW_LEVEL)) {
			b.append(record.getLevel().toString()).append(" ");
		}
		if (logPolicy.isEnabled(LogPolicy.LOG_POLICY_SHOW_CLASS)) {
			b.append("[").append(getSimpleClassName(record.getSourceClassName())).append("]: ");
		}
		if (logPolicy.isEnabled(LogPolicy.LOG_POLICY_SHOW_MESSAGE)) {
			b.append(formatMessage(record));
		}
		if (logPolicy.isEnabled(LogPolicy.LOG_POLICY_SHOW_SOURCE)) {
			b.append(" - (").append(record.getSourceClassName()).append(".java:").append(lineNo).append(") ");
    	}
		if (logPolicy.isEnabled(LogPolicy.LOG_POLICY_SHOW_METHOD)) {
			b.append(record.getSourceMethodName()).append("()");
		}
		if (logPolicy.isEnabled(LogPolicy.LOG_POLICY_SHOW_THREAD)) {
			b.append(" in thread ").append(Thread.currentThread().getName());
		}
		if (logPolicy.dateFormat != null) {
			b.append(" at (").append(logPolicy.dateFormat.format(new Date(record.getMillis()))).append(")");
        }
		b.append("\n").append(stackTrace);
        return b.toString();
	}

	/**
	 * Gets the simple class name.
	 *
	 * @param absolute the absolute class name
	 * @return the simple class name
	 */
	private static String getSimpleClassName(String absolute) {
		String[] parts = absolute.split("\\.");
		return parts[parts.length -1];
	}
	
	/**
	 * A set of boolean properties controlling the content of the log statement
	 * returned by {@link ScandiumFormatter#format(LogRecord)}.
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
			if (df!=null) {
				if (!df.equals("")) {
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
		 * @param propertyName
		 *            the name of the property to add to the policy
		 * @param defaultValue
		 *            the value to fall back to if the {@link LogManager} does
		 *            not contain a value for the configuration property
		 * @return the updated policy
		 */
		private LogPolicy addPolicy(String propertyName, boolean defaultValue) {
			String flag = LogManager.getLogManager().getProperty(propertyName);
			if (flag != null) {
				policy.put(propertyName, Boolean.parseBoolean(flag));
			} else {
				policy.put(propertyName, defaultValue);
			}
			return this;
		}
		
		private boolean isEnabled(String propertyName) {
			Boolean result = policy.get(propertyName);
			return result != null ? result : false;
		}
	}
	
}
