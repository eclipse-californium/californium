/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/

package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.eclipse.californium.elements.util.TestConditionTools.inRange;

import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.Statistic.Summary;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class TimeStatisticTest {

	private static final long TIME_RANGE = 5000;
	private static final long TIME_SLOT = 5;
	TimeStatistic statistic = new TimeStatistic(TIME_RANGE, TIME_SLOT, TimeUnit.MILLISECONDS);

	@Test
	public void testAvg() {
		for (int time = 20; time < 2000; time += 20) {
			statistic.add(time, TimeUnit.MILLISECONDS);
		}
		Summary summary = statistic.getSummary();
		assertThat("count", summary.getCount(), is(99));
		assertThat("average", summary.getAverage(), is(inRange(1000.0D, 1001.0D + TIME_SLOT)));
		assertThat("maximum", summary.getMaximum(), is(1980L));
		statistic.add(4000, TimeUnit.MILLISECONDS);
		summary = statistic.getSummary();
		assertThat("maximum", summary.getMaximum(), is(4000L));
	}

	@Test
	public void testPercentiles() {
		for (int time = 20; time < 2000; time += 20) {
			statistic.add(time, TimeUnit.MILLISECONDS);
		}
		Summary summary = statistic.getSummary(500, 900);
		assertThat("count", summary.getPercentileCount(), is(2));
		assertThat("percentil 50", summary.getPercentileValue(0), is(inRange(1000L, 1001L + TIME_SLOT)));
		assertThat("percentil 90", summary.getPercentileValue(1), is(inRange(1800L, 1801L + TIME_SLOT)));
		statistic.add(4000, TimeUnit.MILLISECONDS);
		summary = statistic.getSummary(500, 900);
		assertThat("percentil 50", summary.getPercentileValue(0), is(inRange(1000L, 1001L + TIME_SLOT)));
		assertThat("percentil 90", summary.getPercentileValue(1), is(inRange(1800L, 1801L + TIME_SLOT)));
	}

	@Test
	public void testRandom() {
		Random random = new Random();
		for (int count = 0; count < 1000; ++count) {
			statistic.add(random.nextInt(200), TimeUnit.MILLISECONDS);
		}
		for (int count = 0; count < 10000; ++count) {
			statistic.add(200 + random.nextInt(800), TimeUnit.MILLISECONDS);
		}
		for (int count = 0; count < 10; ++count) {
			statistic.add(1000 + random.nextInt(1000), TimeUnit.MILLISECONDS);
		}
		Summary summary = statistic.getSummary(950, 990, 999);
		assertThat("count", summary.getPercentileCount(), is(3));
		assertThat("percentil 95", summary.getPercentileValue(0), is(inRange(900L, 1001L)));
		assertThat("percentil 99", summary.getPercentileValue(1), is(inRange(950L, 1001L)));
		assertThat("percentil 99.9", summary.getPercentileValue(2), is(inRange(970L, 1001L)));
	}

}
