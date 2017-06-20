/*******************************************************************************
 * Copyright (c) 2016, 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Unit test cases validating behavior of the {@link Message} class.
 *
 */
@Category(Small.class)
public class MessageTest {

	@Test
	public void testInitalEmptyMessageObservers() {
		Request ping = new Request(null, Type.CON);
		assertThat(ping.getMessageObservers().size(), is(0));
	}

	@Test
	public void testAddMessageObserver() {
		Request ping = new Request(null, Type.CON);
		ping.addMessageObserver(new MessageObserverAdapter() {});
		assertThat(ping.getMessageObservers().size(), is(1));
	}

	@Test
	public void testMultipleAddMessageObserver() {
		Request ping = new Request(null, Type.CON);
		ping.addMessageObserver(new MessageObserverAdapter() {});
		ping.addMessageObserver(new MessageObserverAdapter() {});
		ping.addMessageObserver(new MessageObserverAdapter() {});
		assertThat(ping.getMessageObservers().size(), is(3));
	}

	@Test
	public void testAddEmptyListOfMessageObservers() {
		Request ping = new Request(null, Type.CON);
		List<MessageObserver> observers = Collections.emptyList();
		ping.addMessageObservers(observers);
		assertThat(ping.getMessageObservers().size(), is(0));
	}

	@Test
	public void testAddListOfMessageObservers() {
		Request ping = new Request(null, Type.CON);
		List<MessageObserver> observers = new ArrayList<>();
		observers.add(new MessageObserverAdapter() {});
		observers.add(new MessageObserverAdapter() {});
		ping.addMessageObservers(observers);
		assertThat(ping.getMessageObservers().size(), is(2));
	}

	@Test
	public void testMultipleAddListOfMessageObservers() {
		Request ping = new Request(null, Type.CON);
		List<MessageObserver> observers = new ArrayList<>();
		observers.add(new MessageObserverAdapter() {});
		observers.add(new MessageObserverAdapter() {});
		ping.addMessageObservers(observers);
		observers.add(new MessageObserverAdapter() {});
		observers.add(new MessageObserverAdapter() {});
		ping.addMessageObservers(observers);
		assertThat(ping.getMessageObservers().size(), is(6));
	}

	@Test
	public void testMultipleAddsToMessageObservers() {
		Request ping = new Request(null, Type.CON);
		List<MessageObserver> observers = new ArrayList<>();
		observers.add(new MessageObserverAdapter() {});
		observers.add(new MessageObserverAdapter() {});
		ping.addMessageObservers(observers);
		ping.addMessageObserver(new MessageObserverAdapter() {});
		ping.addMessageObserver(new MessageObserverAdapter() {});
		observers.add(new MessageObserverAdapter() {});
		observers.add(new MessageObserverAdapter() {});
		ping.addMessageObservers(observers);
		ping.addMessageObserver(new MessageObserverAdapter() {});
		assertThat(ping.getMessageObservers().size(), is(9));
	}
}
