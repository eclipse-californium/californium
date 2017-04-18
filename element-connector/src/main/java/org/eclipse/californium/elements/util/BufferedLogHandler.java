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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;

/**
 * Buffered logging handler.
 * 
 * Decouple callers from writing the message into the target. Formats logging
 * messages and stores the messages in a buffer to write them asynchronous to
 * the target handler. This handler also moves the filter from the target
 * handler to execute them ahead.
 * 
 * The main difference to the available {@link java.util.logging.MemoryHandler}
 * is, that the {@link LogRecord} are filtered and expanded synchronous and just
 * writing to the stream is then decoupled. Therefore the formatter is executed
 * in the original thread context and the potential parameter for a formatted
 * message are evaluated synchronous.
 * 
 * Supported logging properties:
 * 
 * <code>
 * org.eclipse.californium.elements.util.BufferedLogHandler.target:
 *      class name of target handler. Default ConsoleHandler.
 *      Note: currently only one handler is supported!
 * 
 * org.eclipse.californium.elements.util.BufferedLogHandler.formatter:
 *      formatter of this handler. Default is the formatter of the target handler.
 *      The formatter of the target handler is then replaced by the 
 *      BufferedOutputFormatter.
 *      Note: the formatter of this handler is used for the first level formatting
 *            and the result is stored in {@link LogRecord#setMessage(String)}.
 *            Therefore the formatter of the target handler should usually be
 *            BufferedOutputFormatter.
 *            
 * org.eclipse.californium.elements.util.BufferedLogHandler.level:
 *      Level of handler. Default is the level of the target handler.
 * 
 * org.eclipse.californium.elements.util.BufferedLogHandler.closingtimeout:
 *      Timeout in milliseconds to wait when closing the handler, until the
 *      last messages are written. Default 0 (wait for ever).
 *      Note: a value bigger then 0 start the logging thread as daemon.
 * 
 * org.eclipse.californium.elements.util.BufferedLogHandler.warningdelaythreshold:
 *      Threshold in milliseconds for the logging delay, when a warning is written.
 *      0 := disable warning. Default 100ms.
 *      
 * </code>
 * 
 * In the most cases, just replace the handler with this and use the original
 * handler as target.
 * 
 * <code>
 * handlers= org.eclipse.californium.elements.util.BufferedLogHandler
 * 
 * org.eclipse.californium.elements.util.BufferedLogHandler.target=java.util.logging.FileHandler
 * </code>
 * 
 * If the target is the java.util.logging.ConsoleHandler, you may even skip to
 * set the target, because it's already the default target.
 * 
 * <code>
 * org.eclipse.californium.elements.util.BufferedLogHandler.target=java.util.logging.ConsoleHandler
 * </code>
 * 
 * Note:
 * 
 * It's currently not supported to use this with multiple handlers. If you use a
 * ConsoleHandler and a FileHandler you can only "buffer" one.
 */
public class BufferedLogHandler extends Handler {

	/**
	 * Instance counter for thread names.
	 */
	private static final AtomicInteger ID_COUNTER = new AtomicInteger();
	/**
	 * Logging property name for target handler.
	 * 
	 * @see #target
	 */
	private static final String PROPERTY_NAME_TARGET = "target";
	/**
	 * Logging property name for formatter.
	 * 
	 * @see #formatter
	 */
	private static final String PROPERTY_NAME_FORMATTER = "formatter";
	/**
	 * Logging property name for closing timeout.
	 * 
	 * @see #closingTimeoutInMs
	 */
	private static final String PROPERTY_NAME_CLOSING_TIMEOUT = "closingtimeout";
	/**
	 * Logging property name for threshold of delay warnings.
	 * 
	 * @see #warningDelayThresholdInMs
	 */
	private static final String PROPERTY_NAME_WARNING_DELAY_THRESHOLD = "warningdelaythreshold";
	/**
	 * Logging property name for logging level.
	 * 
	 * @see #getLevel()
	 */
	private static final String PROPERTY_NAME_LEVEL = "level";
	/**
	 * Default threshold for a delay warning message. Value in milliseconds.
	 * 
	 * @see #warningDelayThresholdInMs
	 */
	private static final long DEFAULT_WARNING_DELAY_THRESHOLD_IN_MS = 100;
	/**
	 * Default timeout for closing this handler. Value in milliseconds.
	 * 
	 * @see #closingTimeoutInMs
	 */
	private static final long DEFAULT_CLOSING_TIMEOUT_IN_MS = 0;

	/**
	 * Thread for writing the messages asynchronous to the target handler.
	 */
	private final Thread thread;
	/**
	 * Target handler.
	 */
	private final Handler target;
	/**
	 * LogRecord formatter.
	 */
	private final Formatter formatter;
	/**
	 * Timeout for {@link Thread#join(long)} on {@link #thread}. Delay
	 * {@link #close()} to ensure, that buffered messages are written to target
	 * handler. Value in milliseconds. 0 := block until all messages are
	 * written.
	 */
	private final long closingTimeoutInMs;
	/**
	 * Threshold for writing a delay warning. Used to detect logging overload or
	 * stream slow down. Values in milliseconds. 0 := disable delay warnings.
	 */
	private final long warningDelayThresholdInMs;
	/**
	 * Set on {@link #close()}.
	 */
	private AtomicBoolean isClosed = new AtomicBoolean();
	/**
	 * Message queue. Contains log records with already expanded
	 * ({@link Formatter#format(LogRecord)} messages.
	 */
	private final BlockingQueue<LogRecord> buffer = new LinkedBlockingQueue<LogRecord>();

	/**
	 * Create new buffered logging handler.
	 * 
	 * Prepare target handler by replacing formatter and filer. Start
	 * {@link #thread}.
	 */
	public BufferedLogHandler() {
		super();
		Handler targetHandler = newInstance(Handler.class, PROPERTY_NAME_TARGET);
		if (null == targetHandler) {
			targetHandler = new ConsoleHandler();
		}
		this.target = targetHandler;
		Formatter formatter = newInstance(Formatter.class, PROPERTY_NAME_FORMATTER);
		if (null == formatter) {
			formatter = targetHandler.getFormatter();
			targetHandler.setFormatter(new BufferedOutputFormatter());
		}
		this.formatter = formatter;
		Level level;
		String levelName = getValue(PROPERTY_NAME_LEVEL);
		if (null != levelName) {
			level = Level.parse(levelName);
		} else {
			level = target.getLevel();
		}
		setLevel(level);

		// move filter
		setFilter(target.getFilter());
		target.setFilter(null);

		closingTimeoutInMs = getLong(PROPERTY_NAME_CLOSING_TIMEOUT, DEFAULT_CLOSING_TIMEOUT_IN_MS);
		warningDelayThresholdInMs = getLong(PROPERTY_NAME_WARNING_DELAY_THRESHOLD,
				DEFAULT_WARNING_DELAY_THRESHOLD_IN_MS);

		LogRecord record = new LogRecord(Level.FINE, "BufferedLogHandler starting ...");
		record.setSourceMethodName("<init>");
		publishTarget(record);

		thread = new Thread("LOG-PUB#" + ID_COUNTER.incrementAndGet()) {

			@Override
			public void run() {
				String closingMessage = "BufferedLogHandler closed.";
				while (!isClosed.get() || !buffer.isEmpty()) {
					try {
						LogRecord record = buffer.take();
						if (0 < warningDelayThresholdInMs) {
							long timeInMs = System.currentTimeMillis();
							long delayInMs = timeInMs - record.getMillis();
							if (warningDelayThresholdInMs < delayInMs) {
								String recordMessage = "D" + delayInMs + "ms " + record.getMessage();
								record.setMessage(recordMessage);
							}
							target.publish(record);
							delayInMs = System.currentTimeMillis() - timeInMs;
							if (warningDelayThresholdInMs < delayInMs) {
								LogRecord warning = new LogRecord(Level.WARNING, "Log delayed! " + delayInMs + " ms");
								warning.setSourceMethodName("out");
								publishTarget(warning);
							}
						} else {
							target.publish(record);
						}
					} catch (InterruptedException e) {
						closingMessage = "BufferedLogHandler closed by interrupt.";
					}
				}
				LogRecord record = new LogRecord(Level.FINE, closingMessage);
				record.setSourceMethodName("close");
				publishTarget(record);
				target.close();
			}
		};
		if (0 < closingTimeoutInMs) {
			thread.setDaemon(true);
		}
		thread.start();
	}

	/**
	 * Get logging property value.
	 * 
	 * @param subProperty sub-property name. Appended to "full.class.name." to
	 *            build the property name.
	 * @return trimmed value of logging property, or null, if not available or
	 *         empty.
	 */
	private String getValue(String subProperty) {
		String value = LogManager.getLogManager().getProperty(BufferedLogHandler.class.getName() + "." + subProperty);
		if (null != value) {
			value = value.trim();
			if (value.isEmpty()) {
				value = null;
			}
		}
		return value;
	}

	/**
	 * Get logging property value as long.
	 * 
	 * @param subProperty sub-property name. Appended to "full.class.name." to
	 *            build the property name.
	 * @param defaultValue default value, if the property is not configured or
	 *            empty.
	 * @return logging property value as long
	 */
	private long getLong(String subProperty, long defaultValue) {
		String value = getValue(subProperty);
		if (null != value) {
			return Long.parseLong(value);
		}
		return defaultValue;
	}

	/**
	 * Create a new instance of class from a logging property value.
	 * 
	 * @param type (super-) type of instance. The new instance is checked to be
	 *            assignable to this type.
	 * @param subProperty sub-property name. Appended to "<class>.<name>." to
	 *            build the property name.
	 * @return new instance, or null, if not configured in logging properties.
	 */
	@SuppressWarnings("unchecked")
	private <T> T newInstance(Class<T> type, String subProperty) {
		String className = getValue(subProperty);
		if (className != null) {
			try {
				Class<?> clz = ClassLoader.getSystemClassLoader().loadClass(className);
				if (type.isAssignableFrom(clz)) {
					return (T) clz.newInstance();
				} else {
					throw new RuntimeException("BufferedHandler \"" + className + "\" is no " + type.getName());
				}
			} catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
				throw new RuntimeException("BufferedHandler can't load \"" + className + "\"", e);
			}
		}
		return null;
	}

	/**
	 * Publish a log record direct to target. Used for internal logging messages
	 * of this implementation.
	 * 
	 * Though the record is not created within the {@link java.util.logging}
	 * package, the {@link LogRecord#inferCaller} could not detect the source.
	 * Therefore this class is set as
	 * {@link LogRecord#setSourceClassName(String)}, and if wanted, the
	 * {@link LogRecord#setSourceMethodName(String)} must be set by the caller.
	 * Note: line number detection is therefore also not working.
	 * 
	 * @param record record to be published.
	 */
	private void publishTarget(LogRecord record) {
		record.setSourceClassName(BufferedLogHandler.class.getName());
		record.setMessage(formatter.format(record));
		target.publish(record);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Pass the record through the level and filters. If
	 * {@link #isLoggable(LogRecord)}, then {@link Formatter#format(LogRecord)}
	 * the record and store the result as {@link LogRecord#setMessage(String)}.
	 * Put the resulting record {@link #buffer}.
	 */
	@Override
	public void publish(LogRecord record) {
		if (!isClosed.get() && isLoggable(record)) {
			record.setMessage(formatter.format(record));
			buffer.offer(record);
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * No effect for asynchronous logging.
	 */
	@Override
	public void flush() {

	}

	/**
	 * {@inheritDoc}
	 * 
	 * Joins the logging thread using {@link #closingTimeoutInMs}. Close the
	 * {@link #target}.
	 */
	@Override
	public void close() throws SecurityException {
		if (isClosed.compareAndSet(false, true)) {
			thread.interrupt();
		}
		try {
			thread.join(closingTimeoutInMs);
		} catch (InterruptedException e) {
		}
		target.close();
	}
}
