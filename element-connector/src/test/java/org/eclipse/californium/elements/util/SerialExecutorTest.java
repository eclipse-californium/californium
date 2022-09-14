/*******************************************************************************
 * Copyright (c) 2022 Contributors to the Eclipse Foundation.
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
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

import org.eclipse.californium.elements.util.SerialExecutor.ExecutionListener;
import org.eclipse.californium.elements.util.SerialExecutor.QueueingListener;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class SerialExecutorTest {

	@Rule
	public ExpectedException exception = ExpectedExceptionWrapper.none();

	@Test
	public void testExecutionListener() {
		TestExecutionListener listener = new TestExecutionListener();
		SerialExecutor executor = new SerialExecutor(TestSynchroneExecutor.TEST_EXECUTOR);
		executor.setExecutionListener(listener);
		executor.execute(new Runnable() {

			@Override
			public void run() {
				// empty by intention
			}
		});
		assertThat(listener.before, is(1));
		assertThat(listener.after, is(1));
	}

	@Test
	public void testExecutionListenerWithException() {
		TestExecutionListener listener = new TestExecutionListener();
		SerialExecutor executor = new SerialExecutor(TestSynchroneExecutor.TEST_EXECUTOR);
		executor.setExecutionListener(listener);
		executor.execute(new Runnable() {

			@Override
			public void run() {
				throw new IntendedTestException("test exception");
			}
		});
		assertThat(listener.before, is(1));
		assertThat(listener.after, is(1));
	}

	@Test
	public void testExecutionListenerWithRejection() {
		TestExecutionListener listener = new TestExecutionListener();
		SerialExecutor executor = new SerialExecutor(new Executor() {

			@Override
			public void execute(Runnable command) {
				throw new RejectedExecutionException("Test rejection.");
			}
		});
		executor.setExecutionListener(listener);
		try {
			executor.execute(new Runnable() {

				@Override
				public void run() {
				}
			});
			fail("Rejection expected!");
		} catch (RejectedExecutionException ex) {

		}
		assertThat(listener.before, is(0));
		assertThat(listener.after, is(0));
	}

	@Test
	public void testQueueingListener() {
		TestQueueingListener listener = new TestQueueingListener();
		SerialExecutor executor = new SerialExecutor(TestSynchroneExecutor.TEST_EXECUTOR);
		executor.execute(listener);
		assertThat(listener.before, is(1));
		assertThat(listener.after, is(1));
	}

	@Test
	public void testQueueingListenerWithException() {
		TestQueueingListener listener = new TestQueueingListener() {

			@Override
			public void run() {
				throw new IntendedTestException("test exception");
			}
		};
		SerialExecutor executor = new SerialExecutor(TestSynchroneExecutor.TEST_EXECUTOR);
		executor.execute(listener);
		assertThat(listener.before, is(1));
		assertThat(listener.after, is(1));
	}

	@Test
	public void testQueueingListenerWithRejection() {
		TestQueueingListener listener = new TestQueueingListener() {

			@Override
			public void onQueueing() {
				throw new RejectedExecutionException("Test rejection.");
			}
		};
		SerialExecutor executor = new SerialExecutor(TestSynchroneExecutor.TEST_EXECUTOR);
		try {
			executor.execute(listener);
			fail("Rejection expected!");
		} catch (RejectedExecutionException ex) {

		}
		assertThat(listener.before, is(0));
		assertThat(listener.after, is(0));
	}

	@Test
	public void testQueueingListenerWithExecutorRejection() {
		TestQueueingListener listener = new TestQueueingListener();
		SerialExecutor executor = new SerialExecutor(new Executor() {

			@Override
			public void execute(Runnable command) {
				throw new RejectedExecutionException("Test rejection.");
			}
		});
		try {
			executor.execute(listener);
			fail("Rejection expected!");
		} catch (RejectedExecutionException ex) {

		}
		assertThat(listener.before, is(1));
		assertThat(listener.after, is(1));
	}

	@Test
	public void testQueueingListenerShutdownNow() {
		TestQueueingListener listener1 = new TestQueueingListener();
		TestQueueingListener listener2 = new TestQueueingListener();
		TestQueueingListener listener3 = new TestQueueingListener();
		TestQueueingListener listener4 = new TestQueueingListener();
		SerialExecutor executor = new SerialExecutor(new Executor() {

			@Override
			public void execute(Runnable command) {
				// empty by intention, ignore command!
			}
		});
		executor.execute(listener1);
		executor.execute(listener2);
		executor.execute(listener3);
		executor.execute(listener4);
		executor.shutdownNow();
		assertThat(listener1.before, is(1));
		// pending current job depends on the target executor
		assertThat(listener1.after, is(0));
		assertThat(listener2.before, is(1));
		assertThat(listener2.after, is(1));
		assertThat(listener3.before, is(1));
		assertThat(listener3.after, is(1));
		assertThat(listener4.before, is(1));
		assertThat(listener4.after, is(1));
	}

	@Test
	public void testSequenceOfSerialExecutorFails() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Sequences of SerialExecutors are not supported!");
		SerialExecutor executor = new SerialExecutor(null);
		new SerialExecutor(executor);
	}

	private static class TestExecutionListener implements ExecutionListener {

		int before;
		int after;

		@Override
		public void beforeExecution() {
			++before;
		}

		@Override
		public void afterExecution() {
			++after;
		}

	}

	private static class TestQueueingListener implements QueueingListener {

		int before;
		int after;

		@Override
		public void onQueueing() {
			++before;
		}

		@Override
		public void onDequeueing() {
			++after;
		}

		@Override
		public void run() {

		}

	}
}
