
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/

package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

/**
 * Test ThreadFactory and predefined ThreadGroups. Ensure, that the predefined
 * ThreadGroups are no daemons, regardless of the ThreadGroup context.
 */
public class NamedThreadFactoryTest {

	@Test
	public void testDaemonThreadGroup() throws Exception {
		ThreadGroup group = new ThreadGroup("test-group");
		group.setDaemon(true);
		createAndStopThread(group);
		assertTrue("group is not destroyed", group.isDestroyed());
	}

	@Test
	public void testNoneDaemonThreadGroup() throws Exception {
		ThreadGroup group = new ThreadGroup("test-group");
		group.setDaemon(false);
		createAndStopThread(group);
		assertFalse("group is destroyed", group.isDestroyed());
	}

	@Test
	public void testLoadedScandiumThreadGroup() throws Exception {
		ThreadGroup parent = new ThreadGroup("parent");
		parent.setDaemon(true);
		// load ThreadFactory from daemon ThreadGroup
		ThreadGroup group = loadInstance(parent, "SCANDIUM_THREAD_GROUP");
		assertFalse("not fresh loaded", group == NamedThreadFactory.SCANDIUM_THREAD_GROUP);
		assertFalse("still daemon", group.isDaemon());
		createAndStopThread(group);
		assertFalse("group is destroyed", group.isDestroyed());
	}

	/**
	 * Creates thread and stop it again.
	 * 
	 * @param group group to create thread.
	 * @throws InterruptedException if thread is interrupted while waiting for
	 *             join.
	 */
	private void createAndStopThread(ThreadGroup group) throws InterruptedException {
		assertThat("group is not empty", group.activeCount(), is(0));
		final CountDownLatch ready = new CountDownLatch(1);
		NamedThreadFactory daemons = new NamedThreadFactory("Test", group);
		assertFalse("group is already destroyed 1", group.isDestroyed());
		Thread thread = daemons.newThread(new Runnable() {

			@Override
			public void run() {
				try {
					ready.await();
				} catch (InterruptedException e) {
				}
			}
		});
		thread.start();
		assertTrue("thread hasn't started", thread.isAlive());
		assertThat("group misses thread", group.activeCount(), is(1));
		assertFalse("group is already destroyed 2", group.isDestroyed());
		ready.countDown();
		thread.join();
		assertFalse("thread is still alive", thread.isAlive());
		assertThat("group is not empty again", group.activeCount(), is(0));
	}

	/**
	 * Load the {@link NamedThreadFactory} and return the provided predefined
	 * thread group, using the context of the provided thread group.
	 * 
	 * @param parent thread group to load the thread factory
	 * @param name name of the predefined thread group. "SCANDIUM_THREAD_GROUP"
	 *            or "COAP_THREAD_GROUP".
	 * @return loaded predefined thread group
	 * @throws Exception if an error occurred during loading
	 */
	private static ThreadGroup loadInstance(ThreadGroup parent, final String name) throws Exception {
		final AtomicReference<Exception> exception = new AtomicReference<Exception>();
		final AtomicReference<ThreadGroup> group = new AtomicReference<ThreadGroup>();
		Thread execute = new Thread(parent, new Runnable() {

			@Override
			public void run() {
				try {
					ThreadGroup loadedGroup = loadInstance(name);
					group.set(loadedGroup);
				} catch (Exception ex) {
					exception.set(ex);
				}
			}
		});
		execute.start();
		execute.join();
		Exception ex = exception.get();
		if (ex != null) {
			throw ex;
		}
		return group.get();
	}

	/**
	 * Load the {@link NamedThreadFactory} and return the provided predefined
	 * thread group.
	 * 
	 * @param name name of the predefined thread group. "SCANDIUM_THREAD_GROUP"
	 *            or "COAP_THREAD_GROUP".
	 * @return loaded predefined thread group
	 * @throws Exception if an error occurred during loading
	 */
	private static ThreadGroup loadInstance(String name) throws Exception {
		ClassLoader loader = new ClassLoader() {

			@Override
			public Class<?> loadClass(String name) throws ClassNotFoundException {
				if (name.startsWith("org.eclipse.californium.")) {
					InputStream input = getClass().getClassLoader()
							.getResourceAsStream(name.replace(".", "/") + ".class");
					if (input != null) {
						try {
							int readlength = 0;
							byte[] buffer = new byte[1024];
							ByteArrayOutputStream output = new ByteArrayOutputStream();
							while ((readlength = input.read(buffer)) != -1) {
								output.write(buffer, 0, readlength);
							}
							byte[] bt = output.toByteArray();
							return defineClass(name, bt, 0, bt.length);
						} catch (IOException e) {
							e.printStackTrace();
							throw new ClassNotFoundException(name + ": read error!");
						}
					} else {
						throw new ClassNotFoundException(name);
					}
				} else {
					return super.loadClass(name);
				}
			}
		};

		Class<?> loadedClass = loader.loadClass(NamedThreadFactory.class.getName());
		Field field = loadedClass.getField(name);
		return (ThreadGroup) field.get(null);
	}
}
