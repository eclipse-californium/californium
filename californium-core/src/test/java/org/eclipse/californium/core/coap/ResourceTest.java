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
package org.eclipse.californium.core.coap;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Collection;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.core.server.resources.ResourceObserver;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Unit test cases validating behavior of the {@link Resource} class.
 *
 */
@Category(Small.class)
public class ResourceTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	CoapResource root;
	CountingResourceObserver counters;

	@Before
	public void setup() {
		counters = new CountingResourceObserver();
		root = new CoapResource("root");
		root.addObserver(counters);
		root.add(new CoapResource("parent1"));
		root.add(new CoapResource("parent2"));
	}

	@Test
	public void testAdd() {
		CoapResource parent = new CoapResource("parent");
		root.add(parent);
		Collection<Resource> children = root.getChildren();
		assertThat(children.size(), is(3));
		assertThat(counters.addedChildCounter, is(3));
		assertThat(counters.removedChildCounter, is(0));
	}

	@Test
	public void testAddTwice() {
		CoapResource parent = new CoapResource("parent");
		root.add(parent);
		root.add(parent);
		Collection<Resource> children = root.getChildren();
		assertThat(children.size(), is(3));
		assertThat(counters.addedChildCounter, is(3));
		assertThat(counters.removedChildCounter, is(0));
	}

	@Test
	public void testAddReplace() {
		CoapResource parent = new CoapResource("parent");
		root.add(parent);
		parent = new CoapResource("parent");
		root.add(parent);
		Collection<Resource> children = root.getChildren();
		assertThat(children.size(), is(3));
		assertThat(counters.addedChildCounter, is(4));
		assertThat(counters.removedChildCounter, is(1));
	}

	@Test
	public void testDelete() {
		CoapResource parent = new CoapResource("parent");
		root.add(parent);
		Collection<Resource> children = root.getChildren();
		assertThat(children.size(), is(3));
		root.delete(parent);
		children = root.getChildren();
		assertThat(children.size(), is(2));
		assertThat(counters.addedChildCounter, is(3));
		assertThat(counters.removedChildCounter, is(1));
	}

	private static class CountingResourceObserver implements ResourceObserver {

		int addedChildCounter;
		int removedChildCounter;

		@Override
		public void changedName(String old) {
		}

		@Override
		public void changedPath(String old) {
		}

		@Override
		public void addedChild(Resource child) {
			addedChildCounter++;
		}

		@Override
		public void removedChild(Resource child) {
			removedChildCounter++;
		}

		@Override
		public void addedObserveRelation(ObserveRelation relation) {

		}

		@Override
		public void removedObserveRelation(ObserveRelation relation) {

		}

	}
}
