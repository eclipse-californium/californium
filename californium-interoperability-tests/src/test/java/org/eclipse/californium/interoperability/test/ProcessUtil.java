/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.interoperability.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNotNull;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * Utility to start external tools.
 */
public class ProcessUtil {

	/**
	 * Process of external tool.
	 */
	private Process process;
	/**
	 * Console output of external tool. Considered to be rather small.
	 */
	private String console = "";
	/**
	 * Result of external tool. RC and console output.
	 */
	private ProcessResult result;

	private volatile boolean stopped;

	/**
	 * Create instance.
	 */
	public ProcessUtil() {
	}

	/**
	 * Shutdown external tool.
	 */
	public void shutdown() throws InterruptedException {
		if (process != null) {
			process.destroy();
			ProcessResult result = waitResult(1000);
			assumeNotNull(result);
			process = null;
			setConsole("");
		}
	}

	public void print(List<String> args) {
		for (String arg : args) {
			System.out.print(arg);
			System.out.print(" ");
		}
		System.out.println();
	}

	/**
	 * Start external tool
	 * 
	 * @param args list of arguments to start the external tool
	 * @throws IOException if start fails.
	 */
	public void execute(String... args) throws IOException {
		execute(Arrays.asList(args));
	}

	/**
	 * Start external tool
	 * 
	 * @param args list of arguments to start the external tool
	 * @throws IOException if start fails.
	 */
	public void execute(List<String> args) throws IOException {
		setConsole("");
		ProcessBuilder builder = new ProcessBuilder(args);
		builder.redirectErrorStream(true);
		process = builder.start();
		startReadingOutput(process);
	}

	/**
	 * Send provided message to the external tools input.
	 * 
	 * @param message message to be written to the external tools input.
	 * @throws IOException if an error occurred when writing
	 */
	public void send(String message) throws IOException {
		if (process != null) {
			System.out.println("< " + message);
			process.getOutputStream().write(message.getBytes());
			process.getOutputStream().flush();
		} else {
			throw new IllegalStateException("process not running");
		}
	}

	/**
	 * Send provided message to the external tools input with line ending added.
	 * 
	 * @param message message to be written with added line ending to the
	 *            external tools input.
	 * @throws IOException if an error occurred when writing
	 */
	public void sendln(String message) throws IOException {
		send(message + StringUtil.lineSeparator());
	}

	/**
	 * Wait for regular expression on console output of external tool.
	 * 
	 * @param regex regular expression
	 * @param timeoutMillis timeout to wait in milliseconds
	 * @return {@code true}, if regular expression could be found in time,
	 *         {@code false}, otherwise.
	 * @throws InterruptedException if waiting was interrupted
	 */
	public synchronized boolean waitConsole(String regex, long timeoutMillis) throws InterruptedException {
		boolean found;
		long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
		Pattern pattern = Pattern.compile(regex);
		while (!(found = pattern.matcher(console).find())) {
			long left = TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime());
			if (left > 0) {
				wait(left);
			} else {
				break;
			}
		}
		return found;
	}

	/**
	 * Assert regular expression on console output of external tool.
	 * 
	 * Waits at most 2000 milliseconds until the external tool has finished.
	 * 
	 * @param regex regular expression
	 * @throws InterruptedException if waiting for result was interrupted
	 */
	public void assertConsole(String regex) throws InterruptedException {
		ProcessResult result = waitResult(2000);
		assertNotNull("process not finished!", result);
		assertTrue("\"" + regex + "\" missing in console output!", result.contains(regex));
	}

	/**
	 * Wait for external tool to finish.
	 * 
	 * Clears {@link #console} as well.
	 * 
	 * @param timeoutMillis timeout to wait in milliseconds
	 * @return result of external tool, or {@code null}, if external tool hasn't
	 *         finished.
	 * @throws InterruptedException if waiting for finish was interrupted
	 */
	public synchronized ProcessResult waitResult(long timeoutMillis) throws InterruptedException {
		if (process != null) {
			long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
			while (result == null) {
				long left = TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime());
				if (left > 0) {
					wait(left);
				} else {
					break;
				}
			}
			if (result != null) {
				process = null;
			}
		}
		return result;
	}

	/**
	 * Stop the process.
	 * 
	 * @throws InterruptedException
	 */
	public void stop() throws InterruptedException {
		if (process != null) {
			stopped = true;
			process.destroy();
		}
	}

	/**
	 * Start reading output.
	 * 
	 * @param process process to read output
	 */
	private void startReadingOutput(final Process process) {
		setResult(null);
		Thread thread = new Thread(new Runnable() {

			@Override
			public void run() {
				try {
					long time = System.nanoTime();
					Reader reader = null;
					StringBuilder console = new StringBuilder();
					try {
						reader = new InputStreamReader(process.getInputStream());
						char[] buffer = new char[2048];
						int read;
						while ((read = reader.read(buffer)) >= 0) {
							if (stopped) {
								break;
							}
							String out = new String(buffer, 0, read);
							System.out.print(out);
							System.out.flush();
							console.append(out);
							setConsole(console.toString());
						}
					} catch (IOException e) {
						if (!stopped) {
							e.printStackTrace();
						}
					} finally {
						if (reader != null) {
							try {
								reader.close();
							} catch (IOException e) {
							}
						}
					}
					int rc = process.waitFor();
					time = System.nanoTime() - time;
					System.out.println(
							"exit: " + process.exitValue() + " (" + TimeUnit.NANOSECONDS.toMillis(time) + "ms).");
					setResult(new ProcessResult(rc, console.toString()));
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		});
		thread.start();
	}

	/**
	 * Set last accumulated console output of external tool.
	 * 
	 * @param console accumulated console output of external tool
	 */
	private synchronized void setConsole(String console) {
		this.console = console;
		notifyAll();
	}

	/**
	 * Set result of external tools
	 * 
	 * @param result result of external tools
	 */
	private synchronized void setResult(ProcessResult result) {
		this.result = result;
		notifyAll();
	}

	/**
	 * Process result.
	 * 
	 * Result of external tool.
	 */
	public static class ProcessResult {

		/**
		 * Return code on finish of external tool.
		 */
		public final int rc;
		/**
		 * Console output of external tool.
		 */
		public final String console;

		/**
		 * Create new result
		 * 
		 * @param rc return code of external tool
		 * @param console accumulated console output of external tool
		 */
		private ProcessResult(int rc, String console) {
			this.rc = rc;
			this.console = console;
		}

		/**
		 * Check, if console output contains a match of the regular expression.
		 * 
		 * @param regex regular expression
		 * @return {@code true}, if match is contained, {@code false},
		 *         otherwise.
		 */
		public boolean contains(String regex) {
			Pattern pattern = Pattern.compile(regex);
			Matcher matcher = pattern.matcher(console);
			return matcher.find();
		}
	}
}
