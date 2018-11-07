/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.util;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.scandium.category.Small;
import org.hamcrest.Description;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class ListUtilsTest {

	public enum Item {
		ONE, TWO, THREE, FOUR, FIVE
	}

	private List<Item> values;

	@Before
	public void setUp() throws Exception {
		values = Arrays.asList(Item.ONE, Item.THREE, Item.FIVE);
	}

	@Test
	public void testInit() {
		assertThat(ListUtils.init(values), is(values));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInitWithMiddleDuplicates() {
		List<Item> values = Arrays.asList(Item.ONE, Item.THREE, Item.FIVE, Item.THREE, Item.TWO);
		List<Item> init = ListUtils.init(values);
		assertThat(init, is(Arrays.asList(Item.ONE, Item.THREE, Item.FIVE, Item.TWO)));
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testInitReturnUnmodifiableList() {
		List<Item> init = ListUtils.init(values);
		init.add(Item.FOUR);
	}

	public static <T> org.hamcrest.Matcher<List<T>> contains(T item) {
		return new Contains<T>(item);
	}

	private static class Contains<T> extends ItemArrayMatcher<T> {

		private Contains(T item) {
			super(item);
		}

		@Override
		public boolean matches(List<T> values) {
			return values.contains(item);
		}

		@Override
		public void describeTo(Description description) {
			description.appendText(item.toString());
			description.appendText(" contained");
		}
	}

	public static <T> org.hamcrest.Matcher<List<T>> isLast(T item) {
		return new IsLast<T>(item);
	}

	private static class IsLast<T> extends ItemArrayMatcher<T> {

		private IsLast(T item) {
			super(item);
		}

		@Override
		public boolean matches(List<T> values) {
			if (values.isEmpty()) {
				return false;
			}
			return values.get(values.size() - 1).equals(item);
		}

		@Override
		public void describeTo(Description description) {
			description.appendText(item.toString());
			description.appendText(" contained");
		}
	}

	private static abstract class ItemArrayMatcher<T> extends org.hamcrest.BaseMatcher<List<T>> {

		protected final T item;

		private ItemArrayMatcher(T item) {
			if (item == null) {
				throw new NullPointerException("item must not be null!");
			}
			this.item = item;
		}

		@Override
		@SuppressWarnings("unchecked")
		public boolean matches(Object values) {
			if (values == null) {
				return false;
			}
			if (!(values instanceof List<?>)) {
				throw new IllegalArgumentException("values type " + values.getClass().getSimpleName() + " is no List");
			}
			return matches((List<T>) values);
		}

		public abstract boolean matches(List<T> values);
	}

	@SafeVarargs
	public static <T> org.hamcrest.Matcher<List<T>> containsAll(T... items) {
		return new ContainsAll<T>(items);
	}

	private static class ContainsAll<T> extends org.hamcrest.BaseMatcher<List<T>> {

		protected final List<T> items;

		@SafeVarargs
		private ContainsAll(T... items) {
			if (items == null) {
				throw new NullPointerException("items must not be null!");
			}
			if (items.length == 0) {
				throw new IllegalArgumentException("items must not be empty!");
			}
			this.items = Arrays.asList(items);
		}

		@Override
		@SuppressWarnings("unchecked")
		public boolean matches(Object values) {
			if (values == null) {
				return false;
			}
			if (!(values instanceof List<?>)) {
				throw new IllegalArgumentException("values type " + values.getClass().getSimpleName() + " is no List");
			}
			List<T> list = (List<T>) values;
			return containsAll(items, list) && containsAll(list, items);
		}

		private boolean containsAll(List<T> list, List<T> contained) {
			for (T item : contained) {
				if (!list.contains(item)) {
					return false;
				}
			}
			return true;
		}

		@Override
		public void describeTo(Description description) {
			description.appendText(items.toString());
			description.appendText(" contained");
		}
	}

}
