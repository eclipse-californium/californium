/*******************************************************************************
 * Copyright (c) 2016, 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Unit test cases validating behavior of the {@link Message} class.
 *
 */
@Category(Small.class)
public class MessageTest {
	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	@Test
	public void testFullRequestHasBlock() {
		Request put = Request.newPut();
		put.setPayload("1234567890ABCDEF1234567890ABCDEF");
		BlockOption start = new BlockOption(0, true, 0);
		assertThat(put.hasBlock(start), is(true));
		BlockOption middle = new BlockOption(0, true, 1);
		assertThat(put.hasBlock(middle), is(true));
		BlockOption end = new BlockOption(0, true, 2);
		assertThat(put.hasBlock(end), is(true));
		BlockOption exceeds = new BlockOption(0, true, 3);
		assertThat(put.hasBlock(exceeds), is(false));
	}

	@Test
	public void testBlockRequestHasBlock() {
		Request put = Request.newPut();
		put.setPayload("1234567890ABCDEF1234567890ABCDEF");
		put.getOptions().setBlock1(0, true, 1);

		BlockOption before = new BlockOption(0, true, 0);
		assertThat(put.hasBlock(before), is(false));
		BlockOption start = new BlockOption(0, true, 1);
		assertThat(put.hasBlock(start), is(true));
		BlockOption middle = new BlockOption(0, true, 2);
		assertThat(put.hasBlock(middle), is(true));
		BlockOption end = new BlockOption(0, true, 3);
		assertThat(put.hasBlock(end), is(true));
		BlockOption exceeds = new BlockOption(0, true, 4);
		assertThat(put.hasBlock(exceeds), is(false));
	}

	@Test
	public void testFullResponseHasBlock() {
		Response content = new Response(ResponseCode.CONTENT);
		content.setPayload("1234567890ABCDEF1234567890ABCDEF");
		BlockOption start = new BlockOption(0, true, 0);
		assertThat(content.hasBlock(start), is(true));
		BlockOption middle = new BlockOption(0, true, 1);
		assertThat(content.hasBlock(middle), is(true));
		BlockOption end = new BlockOption(0, true, 2);
		assertThat(content.hasBlock(end), is(true));
		BlockOption exceeds = new BlockOption(0, true, 3);
		assertThat(content.hasBlock(exceeds), is(false));
	}

	@Test
	public void testBlockResponseHasBlock() {
		Response content = new Response(ResponseCode.CONTENT);
		content.setPayload("1234567890ABCDEF1234567890ABCDEF");
		content.getOptions().setBlock2(0, true, 1);

		BlockOption before = new BlockOption(0, true, 0);
		assertThat(content.hasBlock(before), is(false));
		BlockOption start = new BlockOption(0, true, 1);
		assertThat(content.hasBlock(start), is(true));
		BlockOption middle = new BlockOption(0, true, 2);
		assertThat(content.hasBlock(middle), is(true));
		BlockOption end = new BlockOption(0, true, 3);
		assertThat(content.hasBlock(end), is(true));
		BlockOption exceeds = new BlockOption(0, true, 4);
		assertThat(content.hasBlock(exceeds), is(false));
	}

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
