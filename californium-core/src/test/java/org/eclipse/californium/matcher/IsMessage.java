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
package org.eclipse.californium.matcher;

import java.util.Arrays;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Factory;
import org.hamcrest.Matcher;

/**
 * Tests, if messages have equal serialized representations.
 * 
 * @since 4.0
 */
public class IsMessage<T extends Message> extends BaseMatcher<T> {

	private static DataSerializer serializer = new UdpDataSerializer();
	private final Message message;

	/**
	 * Creates message matcher.
	 * 
	 * @param <T> type of values.
	 * @param message message to check
	 * @return matcher.
	 * @throws NullPointerException if message is {@code null}
	 */
	private IsMessage(Message message) {
		if (null == message) {
			throw new NullPointerException("Message must not be null!");
		}
		this.message = message;
	}

	@Override
	public boolean matches(Object item) {
		if (item == null) {
			throw new NullPointerException("message of type " + message.getClass().getSimpleName()
					+ " missing!");
		}
		if (!message.getClass().equals(item.getClass())) {
			throw new IllegalArgumentException("message type " + item.getClass().getSimpleName()
					+ " doesn't match type " + message.getClass().getSimpleName());
		}
		byte[] data1 = serializer.getByteArray(message);
		byte[] data2 = serializer.getByteArray((Message)item);
		return Arrays.equals(data1, data2);
	}

	@Override
	public void describeTo(Description description) {
		if (message instanceof Request) {
			description.appendText("request[");
			description.appendText(((Request) message).getCode().name());
			description.appendText(",");
		} else if (message instanceof Response) {
			description.appendText("response[");
			description.appendText(((Response) message).getCode().name());
			description.appendText(",");
		} else {
			description.appendText("message[");
		}
		description.appendText(message.getType().name());
		description.appendText("-");
		description.appendText(Integer.toString(message.getMID()));
		description.appendText("]");
	}

	@Override
	public void describeMismatch(Object item, Description mismatchDescription) {
		mismatchDescription.appendValue(item).appendText(" is not ");
		describeTo(mismatchDescription);
	}

	/**
	 * Gets an message matcher.
	 * 
	 * @param <T> type of values.
	 * @param message message to check
	 * @return matcher.
	 * @throws NullPointerException if message is {@code null}
	 */
	@Factory
	public static <T extends Message> Matcher<T> isMessage(T message) {
		return new IsMessage<T>(message);
	}

}
