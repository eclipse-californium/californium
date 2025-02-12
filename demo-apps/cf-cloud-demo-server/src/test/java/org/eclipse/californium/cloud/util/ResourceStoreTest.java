/********************************************************************************
 * Copyright (c) 2025 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.number.OrderingComparison.greaterThan;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.eclipse.californium.cloud.util.ResultConsumer.ResultCode;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Unit tests for resource store.
 * 
 * @since 4.0
 */
public final class ResourceStoreTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(ResourceStoreTest.class);

	@Rule
	public ThreadsRule cleanup = new ThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final File FILE = new File("dummy_unit_test.txt");

	private DeviceManager manager;

	@Before
	public void setup() throws IOException {
		FILE.delete();
		DeviceParser factory = new DeviceParser(true, true, null);
		ResourceStore<DeviceParser> store = new ResourceStore<>(factory).setTag("DevicesTest ");
		store.loadAndCreateMonitor(FILE.getPath(), null, true);
		manager = new DeviceManager(store, null, 5000);
	}

	@Test
	public void testAppendDevice() throws IOException, InterruptedException, ExecutionException {
		final CompletableFuture<ResultCode> result = new CompletableFuture<>();
		String append = "test=tester\n.label='added'\n.psk='test1','secret'\n";
		manager.add(PrincipalInfo.getPrincipalInfo(null), System.currentTimeMillis(), append, (R, M) -> {
			result.complete(R);
			LOGGER.debug("{}", M);
		});
		assertThat(result.get(), is(ResultCode.SUCCESS));
		assertThat(FILE.exists(), is(true));
		long length = FILE.length();
		assertThat(length, is(greaterThan(0L)));

		final CompletableFuture<ResultCode> result2 = new CompletableFuture<>();
		append = "test2=tester\n.label='added'\n.psk='test2','secret'\n";
		manager.add(PrincipalInfo.getPrincipalInfo(null), System.currentTimeMillis(), append, (R, M) -> {
			result2.complete(R);
			LOGGER.debug("{}", M);
		});
		assertThat(result2.get(), is(ResultCode.SUCCESS));
		assertThat(FILE.exists(), is(true));
		long length2 = FILE.length();
		assertThat(length2, is(greaterThan(length)));
	}

}
