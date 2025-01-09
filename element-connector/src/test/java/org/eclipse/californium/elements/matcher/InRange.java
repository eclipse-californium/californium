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
package org.eclipse.californium.elements.matcher;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Factory;
import org.hamcrest.Matcher;

/**
 * Tests, if the argument is a number in the range.
 * 
 * @since 4.0 (moved from TestConditionTools)
 */
public class InRange<T extends Number> extends BaseMatcher<T> {

	/**
	 * Minimum number (inclusive).
	 */
	private final Number min;
	/**
	 * Maximum number (exclusive).
	 */
	private final Number max;

	/**
	 * Creates in range matcher.
	 * 
	 * @param <T> type of values.
	 * @param min inclusive minimum value
	 * @param max exclusive maximum value
	 * @return matcher.
	 * @throws IllegalArgumentException if min is not less than max
	 */
	private InRange(Number min, Number max) {
		if (min instanceof Float || min instanceof Double) {
			if (min.doubleValue() >= max.doubleValue()) {
				throw new IllegalArgumentException("Min " + min + " must be less than max " + max + "!");
			}
		} else {
			if (min.longValue() >= max.longValue()) {
				throw new IllegalArgumentException("Min " + min + " must be less than max " + max + "!");
			}
		}
		this.min = min;
		this.max = max;
	}

	@Override
	public boolean matches(Object item) {
		if (!min.getClass().equals(item.getClass())) {
			throw new IllegalArgumentException("value type " + item.getClass().getSimpleName()
					+ " doesn't match range type " + min.getClass().getSimpleName());
		}
		Number value = (Number) item;
		if (item instanceof Float || item instanceof Double) {
			return min.doubleValue() <= value.doubleValue() && value.doubleValue() < max.doubleValue();
		} else {
			return min.longValue() <= value.longValue() && value.longValue() < max.longValue();
		}
	}

	@Override
	public void describeTo(Description description) {
		description.appendText("range[");
		description.appendText(min.toString());
		description.appendText("-");
		description.appendText(max.toString());
		description.appendText(")");
	}

	@Override
	public void describeMismatch(Object item, Description mismatchDescription) {
		mismatchDescription.appendValue(item).appendText(" is not in ");
		describeTo(mismatchDescription);
	}

	/**
	 * Gets an in range matcher.
	 * 
	 * @param <T> type of values.
	 * @param min inclusive minimum value
	 * @param max exclusive maximum value
	 * @return matcher.
	 * @throws IllegalArgumentException if min is not less than max
	 */
	@Factory
	public static <T extends Number> Matcher<T> inRange(T min, T max) {
		return new InRange<T>(min, max);
	}

}
