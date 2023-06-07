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

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.Statistic.Summary;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class StatisticTest {

	private static final long RANGE = 6;
	private static final long SLOT = 1;
	Statistic statistic = new Statistic(RANGE, SLOT);

	@Test
	public void testAvg() {
		for (int count = 0; count < 6; count++) {
			statistic.add(count);
		}
		Summary summary = statistic.getSummary();
		assertThat("count", summary.getCount(), is(6));
		assertThat("average", summary.getAverage(), is(inRange(2.4D, 2.6D)));
		assertThat("maximum", summary.getMaximum(), is(5L));
		statistic.add(40);
		summary = statistic.getSummary();
		assertThat("maximum", summary.getMaximum(), is(40L));
	}

	@Test
	public void testPercentiles() {
		for (int count = 0; count < 6; count++) {
			statistic.add(count);
		}
		Summary summary = statistic.getSummary(500, 900);
		assertThat("count", summary.getPercentileCount(), is(2));
		assertThat("percentil 50", summary.getPercentileValue(0), is(2L));
		assertThat("percentil 90", summary.getPercentileValue(1), is(5L));
		statistic.add(40);
		summary = statistic.getSummary(500, 900);
		assertThat("percentil 50", summary.getPercentileValue(0), is(3L));
		assertThat("percentil 90", summary.getPercentileValue(1), is(6L));
	}

	@Test
	public void testRandom() {
		Random random = new Random();
		for (int count = 0; count < 1000; ++count) {
			statistic.add(random.nextInt(2));
		}
		for (int count = 0; count < 10000; ++count) {
			statistic.add(2 + random.nextInt(2));
		}
		for (int count = 0; count < 1000; ++count) {
			statistic.add(4 + random.nextInt(2));
		}
		Summary summary = statistic.getSummary(950, 990, 999);
		assertThat("count", summary.getPercentileCount(), is(3));
		assertThat("percentil 95", summary.getPercentileValue(0), is(4L));
		assertThat("percentil 99", summary.getPercentileValue(1), is(5L));
		assertThat("percentil 99.9", summary.getPercentileValue(2), is(5L));
	}

}
