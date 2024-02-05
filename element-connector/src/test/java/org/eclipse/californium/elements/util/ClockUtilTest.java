/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
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
package org.eclipse.californium.elements.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.category.Small;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class ClockUtilTest {

	@Test
	public void testNanoRealtime() {
		long now1 = ClockUtil.nanoRealtime();
		try {
			Thread.sleep(200);
			long now2 = ClockUtil.nanoRealtime();
			assertThat(now2, is(greaterThanOrEqualTo(now1)));
		} catch (InterruptedException e) {
		}
	}

	@Test
	public void testDelta() {
		long now = ClockUtil.nanoRealtime();
		try {
			Thread.sleep(200);
			long delta = ClockUtil.delta(now, TimeUnit.MILLISECONDS);
			assertThat(delta, is(greaterThan(100L)));
		} catch (InterruptedException e) {
		}
		long delta2 = ClockUtil.delta(0, TimeUnit.MILLISECONDS);
		assertThat(delta2, is(0L));
	}

}
