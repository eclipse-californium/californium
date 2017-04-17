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
package org.eclipse.californium.core.test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.StreamHandler;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.CaliforniumFormatter;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Test for meta information in the logging line.
 * 
 * It checks both, Handler and Formatter cooperating together.
 * 
 * Be very careful, when editing this file! The test is very fragile! Though it
 * tests the line number in the logging output, any change requires to adjust
 * the tested resulting line numbers also. (If this shows to be impractical, it
 * may changed to an implementation using Throwable and getStackTrace() to
 * automatically adjust the tested lines.)
 */
@Category(Small.class)
public class LoggerTest {

	/**
	 * Property name to check, if logging is configured proper for this test.
	 */
	private static final String SHOW_SOURCE = "californium.LogPolicy.showSource";
	/**
	 * Logger under test.
	 */
	private static final Logger LOGGER = Logger.getLogger(LoggerTest.class.getName());

	/**
	 * Handler to test the logging output.
	 */
	private TestHandler handler;

	@BeforeClass
	public static void init() {
		LOGGER.setUseParentHandlers(false);
		String configShowSource = LogManager.getLogManager().getProperty(SHOW_SOURCE);
		Assume.assumeFalse("Please enable " + SHOW_SOURCE + ", it's required for this test!",
				"false".equalsIgnoreCase(configShowSource));
	}

	@Before
	public void setup() {
		// remove and close previous handler with TestHandler
		// for this LOGGER only!
		Handler[] handlers = LOGGER.getHandlers();
		for (Handler handlerToRemove : handlers) {
			handlerToRemove.close();
			LOGGER.removeHandler(handlerToRemove);
		}
		handler = new TestHandler();
		LOGGER.addHandler(handler);
	}

	@After
	public void tearDown() {
		LOGGER.removeHandler(handler);
		handler.close();
		handler = null;
	}

	@Test
	public void testLogInfo() throws UnsupportedEncodingException {
		LOGGER.info("message");
		String result = handler.getOutputAsText();
		assertThat(result, containsString(" testLogInfo() "));
		assertThat(result, containsString(".LoggerTest.java:97)"));
	}

	@Test
	public void testLogLevelInfo() throws UnsupportedEncodingException {
		LOGGER.log(Level.INFO, "message");
		String result = handler.getOutputAsText();
		assertThat(result, containsString(" testLogLevelInfo() "));
		assertThat(result, containsString(".LoggerTest.java:105)"));
	}

	@Test
	public void testLogLevelInfoThrowing() throws UnsupportedEncodingException {
		Throwable throwable = new Throwable("test");
		LOGGER.log(Level.INFO, "message", throwable);
		String result = handler.getOutputAsText();
		assertThat(result, containsString(" testLogLevelInfoThrowing() "));
		assertThat(result, containsString(".LoggerTest.java:114)"));
	}

	@Test
	public void testInnerClassLogInfo() throws UnsupportedEncodingException {
		Runnable inner = new Runnable() {

			@Override
			public void run() {
				LOGGER.info("message");
			}
		};
		inner.run();
		String result = handler.getOutputAsText();
		assertThat(result, containsString(" run() "));
		assertThat(result, containsString(".LoggerTest$1.java:126)"));
	}

	@Test
	public void testInnerClassLogLevelInfo() throws UnsupportedEncodingException {
		Runnable inner = new Runnable() {

			@Override
			public void run() {
				LOGGER.log(Level.INFO, "message");
			}
		};
		inner.run();
		String result = handler.getOutputAsText();
		assertThat(result, containsString(" run() "));
		assertThat(result, containsString(".LoggerTest$2.java:141)"));
	}

	@Test
	public void testInnerClassLogLevelInfoThrowing() throws UnsupportedEncodingException {
		final Throwable throwable = new Throwable("test");
		Runnable inner = new Runnable() {

			@Override
			public void run() {
				LOGGER.log(Level.INFO, "message", throwable);
			}
		};
		inner.run();
		String result = handler.getOutputAsText();
		assertThat(result, containsString(" run() "));
		assertThat(result, containsString(".LoggerTest$3.java:157)"));
	}

	/**
	 * Test handler to check the logging output.
	 */
	private class TestHandler extends StreamHandler {

		/**
		 * OutputStream for logging.
		 */
		private ByteArrayOutputStream out = new ByteArrayOutputStream();

		/**
		 * Create handler.
		 */
		public TestHandler() {
			super();
			setOutputStream(out);
			setFormatter(new CaliforniumFormatter());
			setLevel(Level.ALL);
		}

		@Override
		public synchronized void publish(LogRecord record) {
			super.publish(record);
			super.flush();
		}

		/**
		 * Get output as string.
		 * 
		 * @return logging output as string
		 * @throws UnsupportedEncodingException if encoding is not supported
		 */
		public String getOutputAsText() throws UnsupportedEncodingException {
			String encoding = getEncoding();
			if (null != encoding) {
				return out.toString(encoding);
			} else {
				return out.toString();
			}
		}
	}
}
