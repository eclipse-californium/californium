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

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeThat;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.junit.AssumptionViolatedException;

/**
 * Utility to start external tools.
 */
public class ProcessUtil {

	public static final long TIMEOUT_MILLIS = 2000;
	public static final long FOLLOW_UP_TIMEOUT_MILLIS = 100;

	/**
	 * Process of external tool.
	 */
	private Process process;
	/**
	 * Tag for logging.
	 */
	private String tag;

	/**
	 * Realtime nanoseconds of last console output of external tool.
	 * 
	 * @since 3.0
	 */
	private long lastConsoleUpdate = ClockUtil.nanoRealtime();
	/**
	 * Console output of external tool. Considered to be rather small.
	 */
	private String console = "";
	/**
	 * Result of external tool. RC and console output.
	 */
	private ProcessResult result;
	/**
	 * Result of version request of external tool. RC and console output.
	 * 
	 * @since 3.8
	 */
	protected ProcessResult versionResult;
	/**
	 * Version of external tool.
	 * 
	 * @since 3.8
	 */
	protected String version;
	/**
	 * List with extra arguments.
	 * 
	 * @since 3.8
	 */
	protected List<String> extraArgs = new ArrayList<>();

	private boolean stopped;

	private volatile boolean verbose;

	/**
	 * Create instance.
	 */
	public ProcessUtil() {
		setTag("");
	}

	/**
	 * Enable/disable verbose mode.
	 * 
	 * @param verbose {@code true}, enable verbose mode, {@code false}, disable
	 *            it.
	 * @since 3.0
	 */
	public void setDebug(boolean verbose) {
		this.verbose = verbose;
	}

	/**
	 * Shutdown external tool.
	 */
	public void shutdown() throws InterruptedException {
		stop();
		waitResult(TIMEOUT_MILLIS);
		setProcess(null);
		tag = "";
		setConsole("");
	}

	public void print(List<String> args) {
		for (String arg : args) {
			System.out.print(arg);
			System.out.print(" ");
		}
		System.out.println();
	}

	/**
	 * Set logging tag for exit message.
	 * 
	 * @param tag logging tag for exit message
	 * @since 3.0
	 */
	public void setTag(String tag) {
		if (tag == null) {
			tag = "";
		} else if (!tag.isEmpty()) {
			tag = ", " + tag;
		}
		this.tag = tag;
	}

	/**
	 * Clear current extra arguments.
	 * 
	 * @since 3.8
	 */
	public void clearExtraArgs() {
		extraArgs.clear();
	}

	/**
	 * Add extra argument.
	 * 
	 * @param args extra arguments
	 * @since 3.8
	 */
	public void addExtraArgs(String... args) {
		for (String arg : args) {
			extraArgs.add(arg);
		}
	}

	/**
	 * Start external tool.
	 * 
	 * @param args list of arguments to start the external tool
	 * @throws IOException if start fails.
	 */
	public void execute(String... args) throws IOException {
		execute(Arrays.asList(args));
	}

	/**
	 * Start external tool.
	 * 
	 * @param args list of arguments to start the external tool
	 * @throws IOException if start fails.
	 */
	public void execute(List<String> args) throws IOException {
		setConsole("");
		setStopped(false);
		ProcessBuilder builder = new ProcessBuilder(args);
		builder.redirectErrorStream(true);
		Process process = builder.start();
		setProcess(process);
		startReadingOutput(process, tag);
	}

	/**
	 * Send provided message to the external tools input.
	 * 
	 * @param message message to be written to the external tools input.
	 * @throws IOException if an error occurred when writing
	 */
	public void send(String message) throws IOException {
		Process process = getProcess();
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
		long lastConsoleUpdate = this.lastConsoleUpdate;
		long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
		Pattern pattern = Pattern.compile(regex);
		while (!(found = pattern.matcher(console).find())) {
			if (lastConsoleUpdate != this.lastConsoleUpdate) {
				lastConsoleUpdate = this.lastConsoleUpdate;
				end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
			}
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
		ProcessResult result = waitResult(TIMEOUT_MILLIS);
		assertNotNull("process not finished!", result);
		assertTrue("\"" + regex + "\" missing in console output!", result.contains(regex));
	}

	/**
	 * Get external tool's version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of version command. {@code null}, if not available.
	 * @since 3.8
	 */
	public ProcessResult getToolVersion(long timeMillis) {
		return null;
	}

	/**
	 * Get version of external tool.
	 * 
	 * @return version of external tool, or {@code null}, if not available.
	 * @see #getToolVersion(long)
	 * @since 3.8 (moved from LibCoapProcessUtil)
	 */
	public String getVersion() {
		if (versionResult == null) {
			getToolVersion(TIMEOUT_MILLIS);
		}
		return version;
	}

	/**
	 * Compare version with version of external tool.
	 * 
	 * @param version version to compare
	 * @return {@code <0}, if the provided version is newer, {@code 0}, if the
	 *         versions are matching, {@code >0}, if provided version is older.
	 * @see #getToolVersion(long)
	 * @since 3.8 (moved from LibCoapProcessUtil)
	 */
	public int compareVersion(String version) {
		if (versionResult == null) {
			getToolVersion(TIMEOUT_MILLIS);
		}
		assumeThat("version not available!", version, notNullValue());
		return compareVersion(this.version, version);
	}

	/**
	 * Assume a minimum version of the external tool.
	 * 
	 * @param version assumed minimum version
	 * @throws AssumptionViolatedException if the external tool's version is
	 *             older than the provided one.
	 * @see #getToolVersion(long)
	 * @since 3.8 (moved from LibCoapProcessUtil)
	 */
	public void assumeMinVersion(String version) {
		if (versionResult == null) {
			getToolVersion(TIMEOUT_MILLIS);
		}
		assumeNotNull(this.version);
		assumeTrue(this.version + " > " + version, compareVersion(this.version, version) >= 0);
	}

	/**
	 * Compare versions.
	 * 
	 * Split the provided arguments at the {@code '.'}s.
	 * 
	 * @param version1 version 1
	 * @param version2 version 2
	 * @return {@code <0}, if version 1 is older than version 2, {@code 0}, if the
	 *         versions are matching, {@code >0}, if version 1 is newer than
	 *         version2.
	 * @since 3.8 (moved from LibCoapProcessUtil)
	 */
	public static int compareVersion(String version1, String version2) {
		String[] versionPath1 = version1.split("\\.");
		String[] versionPath2 = version2.split("\\.");
		int length = versionPath1.length;
		if (versionPath2.length < length) {
			length = versionPath2.length;
		}
		for (int index = 0; index < length; ++index) {
			int cmp = versionPath1[index].compareTo(versionPath2[index]);
			if (cmp != 0) {
				return cmp;
			}
		}
		return versionPath1.length - versionPath2.length;
	}

	/**
	 * Get console quiet period in milliseconds.
	 * 
	 * @return milliseconds since the last console update.
	 * @since 3.0
	 */
	public long getConsoleQuietMillis() {
		long last;
		synchronized (this) {
			last = lastConsoleUpdate;
		}
		return TimeUnit.NANOSECONDS.toMillis(ClockUtil.nanoRealtime() - last);
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
		Process process = getProcess();
		if (process != null) {
			long lastConsoleUpdate = this.lastConsoleUpdate;
			long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
			while (result == null) {
				if (lastConsoleUpdate != this.lastConsoleUpdate) {
					lastConsoleUpdate = this.lastConsoleUpdate;
					end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
				}
				long left = TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime());
				if (left > 0) {
					wait(left);
				} else {
					break;
				}
			}
			if (result != null) {
				setProcess(null);
			}
		}
		return result;
	}

	/**
	 * Stop the process.
	 * 
	 * @return {@code true}, if stop is forced, {@code false}, otherwise.
	 * @since 3.0 (add return value)
	 */
	public boolean stop() {
		clearExtraArgs();
		Process process = getProcess();
		if (process != null) {
			try {
				process.exitValue();
				System.out.println("process stopped" + tag);
			} catch (IllegalThreadStateException ex) {
				setStopped(true);
				process.destroy();
				System.out.println("process forced stopped" + tag);
				return true;
			}
		}
		return false;
	}

	private synchronized void setStopped(boolean stopped) {
		this.stopped = stopped;
	}

	private synchronized boolean isStopped() {
		return stopped;
	}

	private synchronized void setProcess(Process process) {
		this.process = process;
	}

	private synchronized Process getProcess() {
		return process;
	}

	/**
	 * Start reading output.
	 * 
	 * @param process process to read output
	 * @param tag logging tag for exit message
	 */
	private void startReadingOutput(final Process process, final String tag) {
		setResult(null);
		Thread thread = new Thread(new Runnable() {

			@Override
			public void run() {
				try {
					boolean stopped = false;
					long time = System.nanoTime();
					Reader reader = null;
					StringBuilder console = new StringBuilder();
					try {
						reader = new InputStreamReader(process.getInputStream());
						char[] buffer = new char[2048];
						int read;
						while ((read = reader.read(buffer)) >= 0) {
							stopped = isStopped();
							if (stopped) {
								break;
							}
							String out = new String(buffer, 0, read);
							if (verbose) {
	 							System.out.println("> (" + out.length() + " bytes)");
							}
 							System.out.print(out);
							System.out.flush();
							console.append(out);
							setConsole(console.toString());
						}
					} catch (IOException e) {
						stopped = isStopped();
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
					time = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - time);
					StringBuilder message = new StringBuilder("> exit: ");
					message.append(process.exitValue());
					message.append(" (").append(time).append("ms");
					if (stopped) {
						message.append(", stopped");
					}
					message.append(tag).append(").");
					System.out.println(message);
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
		this.lastConsoleUpdate = ClockUtil.nanoRealtime();
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
			return match(regex) != null;
		}

		/**
		 * Check, if console output contains a match of the regular expression.
		 * 
		 * @param regex regular expression
		 * @return matcher to read groups, {@code null}, if the expression is
		 *         not contained.
		 */
		public Matcher match(String regex) {
			Pattern pattern = Pattern.compile(regex);
			Matcher matcher = pattern.matcher(console);
			if (matcher.find()) {
				return matcher;
			} else {
				return null;
			}
		}
	}
}
