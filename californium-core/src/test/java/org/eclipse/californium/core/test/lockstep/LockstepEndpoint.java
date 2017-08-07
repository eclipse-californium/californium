/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - add newMID to ResponseExpectation
 *    Achim Kraus (Bosch Software Innovations GmbH) - correct mid check. issue #289
 *    Achim Kraus (Bosch Software Innovations GmbH) - use option names for logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - rename loadMID into sameMID
 *    Achim Kraus (Bosch Software Innovations GmbH) - apply source formatter.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add smart deduplication filter.
 *                                                    filter messages based on the last
 *                                                    received messages and the current 
 *                                                    expectation. If the test expect the
 *                                                    message to be repeated, add the mid 
 *                                                    expectation. Change type(Type type)
 *                                                    to accept multiple types (Type... types).
 *                                                    Changed reponseType in type(Type... types)
 *                                                    and storeType().
 *    Achim Kraus (Bosch Software Innovations GmbH) - add assumption for no unintended message
 *                                                    retransmission. If a test fails on
 *                                                    unintended retransmission (caused by
 *                                                    execution time), this changes the test
 *                                                    "fails" into "ignore result". Only
 *                                                    support, if system property
 *                                                    "org.eclipse.californium.junit.starving"
 *                                                    is also set to true.
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Assume;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.Serializer;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.UDPConnector;

public class LockstepEndpoint {
	/**
	 * Name of configuration property for assumption supporting "starving HIPP". 
	 * Supported values of property "true" and "false".
	 * 
	 * @see #assumeNoUnintendedRetransmission
	 */
	public static final String PROPERTY_NAME_STARVING = "org.eclipse.californium.junit.starving";

	public static boolean DEFAULT_VERBOSE = false;

	private UDPConnector connector;
	private InetSocketAddress destination;
	private LinkedBlockingQueue<RawData> incoming;
	/**
	 * Last incoming message.
	 * 
	 * Deduplication is based on that last received message.
	 * 
	 * @see #receiveNextMessage(MidExpectation)
	 */
	private Message lastIncomingMessage;

	private HashMap<String, Object> storage;

	private boolean verbose = DEFAULT_VERBOSE;

	/**
	 * Enable the test to assume, that no unintended message retransmission occurs.
	 * If a test would fail, if a unintended message retransmission was caused by a
	 * timeout, this enables the test to be then ignored rather then fail.
	 * 
	 * @see #PROPERTY_NAME_STARVING
	 * @see #assumeNoUnintendedRetransmission(boolean)
	 */
	private boolean assumeNoUnintendedRetransmission;

	public LockstepEndpoint() {
		this.storage = new HashMap<String, Object>();
		this.incoming = new LinkedBlockingQueue<RawData>();
		this.connector = new UDPConnector(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
		this.connector.setRawDataReceiver(new RawDataChannel() {

			public void receiveData(RawData raw) {
				incoming.offer(raw);
			}
		});

		try {
			connector.start();
			Thread.sleep(100);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public LockstepEndpoint(InetSocketAddress destination) {
		this();
		this.destination = destination;
	}

	public void destroy() {
		if (connector != null) {
			connector.destroy();
		}
	}

	public void print(String text) {
		if (verbose) {
			System.out.println(text);
		}
	}

	/**
	 * Enable or disable the test to assume, that no unintended message
	 * retransmission occurs. Only set, if system property
	 * {@link #PROPERTY_NAME_STARVING} is true. Otherwise
	 * {@link #assumeNoUnintendedRetransmission} is always set to {@code false}.
	 * 
	 * @param enable {@code true} enable the assumption for this test,
	 *            {@code false} disable the assumption
	 * @see #assumeNoUnintendedRetransmission
	 * @see #PROPERTY_NAME_STARVING
	 */
	public void assumeNoUnintendedRetransmission(boolean enable) {
		if (Boolean.getBoolean(PROPERTY_NAME_STARVING)) {
			this.assumeNoUnintendedRetransmission = enable;
		} else {
			this.assumeNoUnintendedRetransmission = false;
		}
	}

	public void setVerbose(boolean v) {
		this.verbose = v;
	}

	public boolean isVerbose() {
		return verbose;
	}

	public int getPort() {
		return connector.getAddress().getPort();
	}

	public InetAddress getAddress() {
		return connector.getAddress().getAddress();
	}

	public Object get(String var) {
		return storage.get(var);
	}

	/**
	 * Get MID from stored values.
	 * 
	 * The MID may be stored either by
	 * {@link MessageExpectation#storeMID(String)} or
	 * {@link MessageExpectation#storeBoth(String)}.
	 * 
	 * @param var name of variable
	 * @return MID
	 * @throws NoSuchElementException, if nothing so stored under the name, or
	 *             the item doesn't contain a MID.
	 */
	public int getMID(String var) {
		Object item = storage.get(var);
		if (null != item) {
			if (item instanceof Integer) {
				// saveMID
				return (Integer) item;
			}
			if (item instanceof Object[]) {
				// saveBoth
				Object[] items = (Object[]) item;
				return (Integer) items[0];
			}
			throw new NoSuchElementException("Variable '" + var + "' is no MID (" + item.getClass() + ")");
		}
		throw new NoSuchElementException("No variable '" + var + "'");
	}

	public RequestExpectation expectRequest() {
		return new RequestExpectation();
	}

	public RequestExpectation expectRequest(Type type, Code code, String path) {
		return new RequestExpectation().type(type).code(code).path(path);
	}

	public ResponseExpectation expectResponse() {
		return new ResponseExpectation();
	}

	public ResponseExpectation expectResponse(Type type, ResponseCode code, byte[] token, int mid) {
		return expectResponse().type(type).code(code).token(token).mid(mid);
	}

	public EmptyMessageExpectation expectEmpty(Type type, int mid) {
		return new EmptyMessageExpectation(type, mid);
	}

	public RequestProperty sendRequest(Type type, Code code, byte[] token, int mid) {
		if (type == null) {
			throw new NullPointerException();
		}
		if (code == null) {
			throw new NullPointerException();
		}
		if (token == null) {
			throw new NullPointerException();
		}
		if (mid < 0 || mid > (1 << 16) - 1) {
			throw new RuntimeException();
		}
		return new RequestProperty(type, code, token, mid);
	}

	public ResponseProperty sendResponse(Type type, ResponseCode code) {
		if (type == null) {
			throw new NullPointerException();
		}
		if (code == null) {
			throw new NullPointerException();
		}
		return new ResponseProperty(type, code);
	}

	public EmptyMessageProperty sendEmpty(Type type) {
		if (type == null) {
			throw new NullPointerException();
		}
		return sendEmpty(type, Message.NONE);
	}

	public EmptyMessageProperty sendEmpty(Type type, int mid) {
		return new EmptyMessageProperty(type, mid);
	}

	public void send(RawData raw) {
		if (raw.getAddress() == null || raw.getPort() == 0) {
			throw new RuntimeException("Message has no destination address/port");
		}
		connector.send(raw);
	}

	public void setDestination(InetSocketAddress destination) {
		this.destination = destination;
	}

	/**
	 * Receive next message.
	 * 
	 * Apply smart deduplication based on {@link #lastIncomingMessage} and the
	 * MID, if the repeated MID is not expected. If no next message arrives,
	 * reports an assert.
	 * 
	 * <code>
	 *    ... expectRequest.storeMID("A").type(CON) ...
	 * 
	 *        // wait until retransmission
	 * 
	 *        // OK, expecting the MID suppresses deduplication
	 *    ... expectRequest.sameMID("A").type(CON) ... 
	 *        // will fail, not expecting the MID, 
	 *        // the retransmission would be dropped by deduplication
	 *    ... expectRequest.type(CON)... 
	 * 
	 * </code>
	 * 
	 * MID expectations are based on {@link MessageExpectation#mid(int)},
	 * {@link MessageExpectation#sameMID(String)} or
	 * {@link MessageExpectation#sameBoth(String)}.
	 * 
	 * @param midExpectation MID expectation
	 * @return next received message
	 * @throws InterruptedException if waiting for message is interrupted.
	 */
	public Message receiveNextMessage(MidExpectation midExpectation) throws InterruptedException {
		while (true) {
			RawData raw = incoming.poll(2, TimeUnit.SECONDS); // or take()?
			Assert.assertNotNull("did not receive message within expected time frame (2 secs)", raw);

			Message msg;
			DataParser parser = new DataParser(raw.getBytes());
			if (parser.isEmpty()) {
				msg = parser.parseEmptyMessage();
			} else if (parser.isResponse()) {
				msg = parser.parseResponse();
			} else if (parser.isRequest()) {
				msg = parser.parseRequest();
			} else {
				Assert.fail("Message type unknown");
				return null; // never reached
			}
			if (null != midExpectation && null != lastIncomingMessage && lastIncomingMessage.getMID() == msg.getMID()
					&& lastIncomingMessage.getType() == msg.getType() && !midExpectation.expectMID(msg)) {
				// received message with same MID but not expected
				// => discard message!
				Assume.assumeFalse("Unintended message retransmission would cause the test to fail! " + msg, assumeNoUnintendedRetransmission);
				print("discarding duplicate message: " + msg);
			} else {
				msg.setSource(raw.getAddress());
				msg.setSourcePort(raw.getPort());
				lastIncomingMessage = msg;
				return msg;
			}
		}
	}

	public abstract class MessageExpectation implements Action, MidExpectation {

		/**
		 * List of MID expectation. Used for smart deduplication.
		 */
		private List<MidExpectation> midExpectations = new LinkedList<MidExpectation>();
		private List<Expectation<Message>> expectations = new LinkedList<Expectation<Message>>();

		public MessageExpectation mid(final int mid) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					Assert.assertEquals("Wrong MID:", mid, message.getMID());
					print("Correct MID: " + mid);
				}
			});
			midExpectations.add(new MidExpectation() {

				@Override
				public boolean expectMID(Message message) {
					return message.getMID() == mid;
				}

			});
			return this;
		}

		public MessageExpectation sameMID(final String var) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					int expected = getMID(var);
					Assert.assertEquals("Wrong MID:", expected, message.getMID());
					print("Correct MID: " + expected);
				}
			});
			midExpectations.add(new MidExpectation() {

				@Override
				public boolean expectMID(Message message) {
					int expected = getMID(var);
					return message.getMID() == expected;
				}

			});
			return this;
		}

		/**
		 * Check, if the MID of the response is not already contained in the MID
		 * set with the provided name. After the check, add the MID to the set.
		 * 
		 * Provides a fluent API to chain expectations.
		 * 
		 * @param var name of MID set
		 * @return this MessageExpectation
		 */
		public MessageExpectation newMID(final String var) {
			expectations.add(new Expectation<Message>() {

				@Override
				public void check(final Message response) {
					final int mid = response.getMID();
					@SuppressWarnings("unchecked")
					Set<Integer> usedMIDs = (Set<Integer>) storage.get(var);
					if (usedMIDs != null && !usedMIDs.isEmpty()) {
						Assert.assertFalse("MID: " + mid + " is not new! " + usedMIDs, usedMIDs.contains(mid));
					}
					if (usedMIDs == null) {
						usedMIDs = new HashSet<Integer>();
					}
					usedMIDs.add(mid);
					storage.put(var, usedMIDs);
				}
			});
			return this;
		}

		public MessageExpectation type(final Type... types) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					Type type = message.getType();
					Assert.assertTrue("Unexpected type: " + type + ", expected: " + Arrays.toString(types),
							Arrays.asList(types).contains(type));
				}
			});
			return this;
		}

		public MessageExpectation token(final byte[] token) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					org.junit.Assert.assertArrayEquals("Wrong token:", token, message.getToken());
					print("Correct token: " + Utils.toHexString(token));
				}
			});
			return this;
		}

		public MessageExpectation payload(final String payload) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					int expectedLength = payload.length();
					int actualLength = message.getPayloadSize();
					Assert.assertEquals("Wrong payload length: ", expectedLength, actualLength);
					Assert.assertEquals("Wrong payload:", payload, message.getPayloadString());
					print("Correct payload (" + actualLength + " bytes):" + System.lineSeparator()
							+ message.getPayloadString());
				}
			});
			return this;
		}

		public MessageExpectation payload(String payload, int from, int to) {
			payload(payload.substring(from, to));
			return this;
		}

		public MessageExpectation block1(final int num, final boolean m, final int size) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					Assert.assertTrue("No Block1 option:", message.getOptions().hasBlock1());
					BlockOption block1 = message.getOptions().getBlock1();
					Assert.assertEquals("Wrong Block1 num:", num, block1.getNum());
					Assert.assertEquals("Wrong Block1 m:", m, block1.isM());
					Assert.assertEquals("Wrong Block1 size:", size, block1.getSize());
					print("Correct Block1 option: " + block1);
				}
			});
			return this;
		}

		public MessageExpectation block2(final int num, final boolean m, final int size) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					Assert.assertTrue("No Block2 option:", message.getOptions().hasBlock2());
					BlockOption block2 = message.getOptions().getBlock2();
					Assert.assertEquals("Wrong Block2 num:", num, block2.getNum());
					Assert.assertEquals("Wrong Block2 m:", m, block2.isM());
					Assert.assertEquals("Wrong Block2 size:", size, block2.getSize());
					print("Correct Block2 option: " + block2);
				}
			});
			return this;
		}

		public MessageExpectation observe(final int observe) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					Assert.assertTrue("No observe option:", message.getOptions().hasObserve());
					int actual = message.getOptions().getObserve();
					Assert.assertEquals("Wrong observe sequence number:", observe, actual);
					print("Correct observe sequence number: " + observe);
				}
			});
			return this;
		}

		public MessageExpectation noOption(final int... numbers) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					List<Option> options = message.getOptions().asSortedList();
					for (Option option : options) {
						for (int n : numbers) {
							if (option.getNumber() == n) {
								Assert.fail("Must not have option number " + n + " but has " + option);
							}
						}
					}
				}
			});
			return this;
		}

		public MessageExpectation storeMID(final String var) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					storage.put(var, message.getMID());
				}
			});
			return this;
		}

		public MessageExpectation storeToken(final String var) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					storage.put(var, message.getToken());
				}
			});
			return this;
		}

		public MessageExpectation storeBoth(final String var) {
			expectations.add(new Expectation<Message>() {

				public void check(final Message request) {
					Object[] pair = new Object[2];
					pair[0] = request.getMID();
					pair[1] = request.getToken();
					storage.put(var, pair);
				}
			});
			return this;
		}

		public MessageExpectation sameBoth(final String var) {
			expectations.add(new Expectation<Message>() {

				@Override
				public void check(Message message) {
					Object[] pair = (Object[]) storage.get(var);
					Assert.assertEquals("Wrong MID:", pair[0], message.getMID());
					Assert.assertArrayEquals("Wrong token:", (byte[]) pair[1], message.getToken());
					print("Correct MID: " + message.getMID() + " and token: " + Utils.toHexString(message.getToken()));
				}

			});
			midExpectations.add(new MidExpectation() {

				@Override
				public boolean expectMID(Message message) {
					int expected = getMID(var);
					return message.getMID() == expected;
				}

			});
			return this;
		}

		public void check(Message message) {
			for (Expectation<Message> expectation : expectations) {
				expectation.check(message);
			}
		}

		/**
		 * Check, if the message with the contained MID is expected.
		 * 
		 * @param message message to check
		 * @return true, message is expected, don't drop it for deduplication.
		 *         false, message is not expected and could be dropped.
		 */
		public boolean expectMID(Message message) {
			for (MidExpectation expectation : midExpectations) {
				if (expectation.expectMID(message)) {
					return true;
				}
			}
			return false;
		}

	}

	public class RequestExpectation extends MessageExpectation {

		private List<Expectation<Request>> expectations = new LinkedList<LockstepEndpoint.Expectation<Request>>();

		@Override
		public RequestExpectation mid(final int mid) {
			super.mid(mid);
			return this;
		}

		@Override
		public RequestExpectation type(final Type... type) {
			super.type(type);
			return this;
		}

		@Override
		public RequestExpectation token(final byte[] token) {
			super.token(token);
			return this;
		}

		@Override
		public RequestExpectation payload(final String payload) {
			super.payload(payload);
			return this;
		}

		@Override
		public RequestExpectation payload(String payload, int from, int to) {
			super.payload(payload, from, to);
			return this;
		}

		@Override
		public RequestExpectation block1(final int num, final boolean m, final int size) {
			super.block1(num, m, size);
			return this;
		}

		@Override
		public RequestExpectation block2(final int num, final boolean m, final int size) {
			super.block2(num, m, size);
			return this;
		}

		@Override
		public RequestExpectation observe(final int observe) {
			super.observe(observe);
			return this;
		}

		@Override
		public RequestExpectation noOption(final int... numbers) {
			super.noOption(numbers);
			return this;
		}

		@Override
		public RequestExpectation storeMID(final String var) {
			super.storeMID(var);
			return this;
		}

		@Override
		public MessageExpectation storeToken(final String var) {
			super.storeToken(var);
			return this;
		}

		public RequestExpectation storeBoth(final String var) {
			super.storeBoth(var);
			return this;
		}

		@Override
		public RequestExpectation sameBoth(final String var) {
			super.sameBoth(var);
			return this;
		}

		public RequestExpectation code(final Code code) {
			expectations.add(new Expectation<Request>() {

				public void check(Request request) {
					Assert.assertEquals(code, request.getCode());
					print("Correct code: " + code + " (" + code.value + ")");
				}
			});
			return this;
		}

		public RequestExpectation path(final String path) {
			expectations.add(new Expectation<Request>() {

				public void check(Request request) {
					Assert.assertEquals(path, request.getOptions().getUriPathString());
					print("Correct URI path: " + path);
				}
			});
			return this;
		}

		public void check(Request request) {
			super.check(request);
			for (Expectation<Request> expectation : expectations) {
				expectation.check(request);
			}
		}

		@Override
		public void go() throws Exception {
			Message msg = receiveNextMessage(this);

			if (msg instanceof Request) {
				Request request = (Request) msg;
				check(request);
			} else {
				Assert.fail("Expected request but received " + msg);
			}
		}
	}

	public class ResponseExpectation extends MessageExpectation {

		private List<Expectation<Response>> expectations = new LinkedList<LockstepEndpoint.Expectation<Response>>();

		@Override
		public ResponseExpectation mid(final int mid) {
			super.mid(mid);
			return this;
		}

		@Override
		public ResponseExpectation type(final Type... type) {
			super.type(type);
			return this;
		}

		@Override
		public ResponseExpectation token(final byte[] token) {
			super.token(token);
			return this;
		}

		@Override
		public ResponseExpectation payload(final String payload) {
			super.payload(payload);
			return this;
		}

		@Override
		public ResponseExpectation payload(String payload, int from, int to) {
			super.payload(payload, from, to);
			return this;
		}

		@Override
		public ResponseExpectation block1(final int num, final boolean m, final int size) {
			super.block1(num, m, size);
			return this;
		}

		@Override
		public ResponseExpectation block2(final int num, final boolean m, final int size) {
			super.block2(num, m, size);
			return this;
		}

		@Override
		public ResponseExpectation observe(final int observe) {
			super.observe(observe);
			return this;
		}

		@Override
		public ResponseExpectation noOption(final int... numbers) {
			super.noOption(numbers);
			return this;
		}

		@Override
		public ResponseExpectation storeMID(final String var) {
			super.storeMID(var);
			return this;
		}

		@Override
		public ResponseExpectation sameMID(final String var) {
			super.sameMID(var);
			return this;
		}

		@Override
		public ResponseExpectation newMID(final String var) {
			super.newMID(var);
			return this;
		}

		public ResponseExpectation code(final ResponseCode code) {
			expectations.add(new Expectation<Response>() {

				public void check(Response response) {
					Assert.assertEquals(code, response.getCode());
					print("Correct code: " + code + " (" + code.value + ")");
				}
			});
			return this;
		}

		public ResponseExpectation storeType(final String key) {
			expectations.add(new Expectation<Response>() {

				public void check(Response response) {
					Type type = response.getType();
					storage.put(key, type);
				}
			});
			return this;
		}

		public ResponseExpectation storeObserve(final String key) {
			expectations.add(new Expectation<Response>() {

				public void check(Response response) {
					Assert.assertTrue("Has no observe option", response.getOptions().hasObserve());
					storage.put(key, response.getOptions().getObserve());
				}
			});
			return this;
		}

		public ResponseExpectation largerObserve(final String key) {
			expectations.add(new Expectation<Response>() {

				public void check(Response response) {
					Assert.assertTrue("Has no observe option", response.getOptions().hasObserve());
					Object value = storage.get(key);
					if (value == null) {
						throw new IllegalArgumentException("Key " + key + " not found");
					}
					int V1 = (Integer) value;
					int V2 = response.getOptions().getObserve();
					boolean fresh = V1 < V2 && V2 - V1 < 1 << 23 || V1 > V2 && V1 - V2 > 1 << 23;
					Assert.assertTrue("Was not a fresh notification. Last obs=" + V1 + ", new=" + V2, fresh);
				}
			});
			return this;
		}

		public ResponseExpectation checkObs(String former, String next) {
			largerObserve(former);
			storeObserve(next);
			return this;
		}

		public ResponseExpectation loadObserve(final String key) {
			expectations.add(new Expectation<Response>() {

				public void check(Response response) {
					Assert.assertTrue("No observe option:", response.getOptions().hasObserve());
					int expected = (Integer) storage.get(key);
					int actual = response.getOptions().getObserve();
					Assert.assertEquals("Wrong observe sequence number:", expected, actual);
					print("Correct observe sequence number: " + expected);
				}
			});
			return this;
		}

		public void check(Response response) {
			super.check(response);
			for (Expectation<Response> expectation : expectations) {
				expectation.check(response);
			}
		}

		public void go() throws Exception {
			Message msg = receiveNextMessage(this);

			if (msg instanceof Response) {
				Response response = (Response) msg;
				check(response);
			} else {
				Assert.fail("Expected response but received " + msg);
			}
		}

	}

	public class EmptyMessageExpectation extends MessageExpectation {

		public EmptyMessageExpectation(Type type, int mid) {
			super();
			type(type).mid(mid);
		}

		@Override
		public void go() throws Exception {
			Message msg = receiveNextMessage(this);

			if (msg instanceof EmptyMessage) {
				EmptyMessage empty = (EmptyMessage) msg;
				check(empty);
			} else {
				Assert.fail("Expected empty message but received " + msg);
			}
		}
	}

	public static interface Expectation<T> {

		public void check(T t);
	}

	public static interface Property<T> {

		public void set(T t);
	}

	public abstract class MessageProperty implements Action {

		private List<Property<Message>> properties = new LinkedList<LockstepEndpoint.Property<Message>>();

		private Type type;
		private byte[] token;
		private int mid;

		public MessageProperty(Type type) {
			this.type = type;
		}

		public MessageProperty(Type type, byte[] token, int mid) {
			this.type = type;
			this.token = token;
			this.mid = mid;
		}

		public void setProperties(Message message) {
			message.setType(type);
			message.setToken(token);
			message.setMID(mid);
			for (Property<Message> property : properties) {
				property.set(message);
			}
		}

		public MessageProperty mid(final int mid) {
			this.mid = mid;
			return this;
		}

		public MessageProperty block1(final int num, final boolean m, final int size) {
			properties.add(new Property<Message>() {

				public void set(Message message) {
					message.getOptions().setBlock1(BlockOption.size2Szx(size), m, num);
				}
			});
			return this;
		}

		public MessageProperty block2(final int num, final boolean m, final int size) {
			properties.add(new Property<Message>() {

				public void set(Message message) {
					message.getOptions().setBlock2(BlockOption.size2Szx(size), m, num);
				}
			});
			return this;
		}

		public MessageProperty observe(final int observe) {
			properties.add(new Property<Message>() {

				public void set(Message message) {
					message.getOptions().setObserve(observe);
				}
			});
			return this;
		}

		public MessageProperty loadMID(final String var) {
			properties.add(new Property<Message>() {

				public void set(Message message) {
					int mid = (Integer) storage.get(var);
					message.setMID(mid);
				}
			});
			return this;
		}

		public MessageProperty loadToken(final String var) {
			properties.add(new Property<Message>() {

				public void set(Message message) {
					byte[] tok = (byte[]) storage.get(var);
					message.setToken(tok);
				}
			});
			return this;
		}
	}

	public class EmptyMessageProperty extends MessageProperty {

		public EmptyMessageProperty(Type type, int mid) {
			super(type, new byte[0], mid);
		}

		@Override
		public void go() {
			EmptyMessage message = new EmptyMessage(null);
			if (destination != null) {
				message.setDestination(destination.getAddress());
				message.setDestinationPort(destination.getPort());
			}
			setProperties(message);

			Serializer serializer = new Serializer();
			RawData raw = serializer.serialize(message);
			send(raw);
		}
	}

	public class RequestProperty extends MessageProperty {

		private List<Property<Request>> properties = new LinkedList<LockstepEndpoint.Property<Request>>();

		private Code code;

		public RequestProperty(Type type, Code code, byte[] token, int mid) {
			super(type, token, mid);
			this.code = code;
		}

		@Override
		public RequestProperty mid(final int mid) {
			super.mid(mid);
			return this;
		}

		@Override
		public RequestProperty block1(final int num, final boolean m, final int size) {
			super.block1(num, m, size);
			return this;
		}

		@Override
		public RequestProperty block2(final int num, final boolean m, final int size) {
			super.block2(num, m, size);
			return this;
		}

		@Override
		public RequestProperty observe(final int observe) {
			super.observe(observe);
			return this;
		}

		public RequestProperty payload(final String payload) {
			properties.add(new Property<Request>() {

				public void set(Request request) {
					request.setPayload(payload);
				}
			});
			return this;
		}

		public RequestProperty path(final String path) {
			properties.add(new Property<Request>() {

				public void set(Request request) {
					request.getOptions().setUriPath(path);
				}
			});
			return this;
		}

		public void setProperties(Request request) {
			super.setProperties(request);
			for (Property<Request> property : properties)
				property.set(request);
		}

		@Override
		public void go() {
			Request request = new Request(code);
			if (destination != null) {
				request.setDestination(destination.getAddress());
				request.setDestinationPort(destination.getPort());
			}
			setProperties(request);

			Serializer serializer = new Serializer();
			RawData raw = serializer.serialize(request);
			send(raw);
		}
	}

	public class ResponseProperty extends MessageProperty {

		private List<Property<Response>> properties = new LinkedList<LockstepEndpoint.Property<Response>>();

		private ResponseCode code;

		public ResponseProperty(Type type, ResponseCode code) {
			super(type);
			this.code = code;
		}

		@Override
		public ResponseProperty loadToken(final String var) {
			super.loadToken(var);
			return this;
		}

		@Override
		public ResponseProperty loadMID(final String var) {
			super.loadMID(var);
			return this;
		}

		@Override
		public ResponseProperty mid(final int mid) {
			super.mid(mid);
			return this;
		}

		@Override
		public ResponseProperty block1(final int num, final boolean m, final int size) {
			super.block1(num, m, size);
			return this;
		}

		@Override
		public ResponseProperty block2(final int num, final boolean m, final int size) {
			super.block2(num, m, size);
			return this;
		}

		@Override
		public ResponseProperty observe(final int observe) {
			super.observe(observe);
			return this;
		}

		public ResponseProperty payload(final String payload) {
			properties.add(new Property<Response>() {

				public void set(Response response) {
					response.setPayload(payload);
				}
			});
			return this;
		}

		public ResponseProperty path(final String path) {
			properties.add(new Property<Response>() {

				public void set(Response response) {
					response.getOptions().setUriPath(path);
				}
			});
			return this;
		}

		public ResponseProperty loadBoth(final String var) {
			properties.add(new Property<Response>() {

				public void set(Response response) {
					Object[] pair = (Object[]) storage.get(var);
					if (pair == null) {
						throw new NullPointerException(
								"Did not find MID and token for variable " + var + ". Did you forgot a go()?");
					}
					response.setMID((Integer) pair[0]);
					response.setToken((byte[]) pair[1]);
				}
			});
			return this;
		}

		public void setProperties(Response response) {
			super.setProperties(response);
			for (Property<Response> property : properties) {
				property.set(response);
			}
		}

		@Override
		public void go() {
			Response response = new Response(code);
			if (destination != null) {
				response.setDestination(destination.getAddress());
				response.setDestinationPort(destination.getPort());
			}
			setProperties(response);

			Serializer serializer = new Serializer();
			RawData raw = serializer.serialize(response);
			send(raw);
		}
	}

	public static interface Action {

		/**
		 * The method go() must be called when an action is ready. If you think
		 * there is a smarter way than such a method at the end of each action,
		 * first make sure the smarter way also works for sending messages
		 * before changing this.
		 */
		public void go() throws Exception;
	}

	public static interface MidExpectation {

		public boolean expectMID(Message message);
	}

}
