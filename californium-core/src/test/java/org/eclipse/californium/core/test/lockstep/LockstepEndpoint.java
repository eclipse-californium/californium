/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use static reference to Serializer
 *    Achim Kraus (Bosch Software Innovations GmbH) - apply source formatter
 *    Achim Kraus (Bosch Software Innovations GmbH) - add newMID to ResponseExpectation
 *    Achim Kraus (Bosch Software Innovations GmbH) - correct mid check. issue #289
 *    Achim Kraus (Bosch Software Innovations GmbH) - use option names for logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - rename loadMID into sameMID
 *    Achim Kraus (Bosch Software Innovations GmbH) - add smart deduplication filter.
 *                                                    filter messages based on the last
 *                                                    received messages and the current
 *                                                    expectation. If the test expect the
 *                                                    message to be repeated, add the mid
 *                                                    expectation. Change type(Type type)
 *                                                    to accept multiple types (Type... types).
 *                                                    Changed reponseType in type(Type... types)
 *                                                    and storeType().
 *    Achim Kraus (Bosch Software Innovations GmbH) - add getToken(String) to access
 *                                                    both stored representations
 *                                                    ("token" and "both").
 *                                                    Adjust usage to getMID(String) and
 *                                                    getToken(String) and add some methods
 *                                                    to use them.
 *                                                    Split receiveNextMessage into
 *                                                    receiveNextMessage and
 *                                                    receiveNextExpectedMessage
 *                                                    to check, if still messages
 *                                                    arrive.
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 *    Achim Kraus (Bosch Software Innovations GmbH) - add support for TimeAssume
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.coap.option.OptionDefinition;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.assume.TimeAssume;
import org.eclipse.californium.elements.config.Configuration;
import org.junit.AssumptionViolatedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LockstepEndpoint {
	private static final Logger LOGGER = LoggerFactory.getLogger(LockstepEndpoint.class);

	private static boolean DEFAULT_VERBOSE = false;

	private UDPConnector connector;
	private InetSocketAddress destination;
	private LinkedBlockingQueue<RawData> incoming;
	/**
	 * Last incoming message.
	 * 
	 * Deduplication is based on that last received message.
	 * 
	 * @see #receiveNextExpectedMessage(MidExpectation)
	 */
	private Message lastIncomingMessage;

	private HashMap<String, Object> storage;

	private final DataSerializer serializer;
	private final DataParser parser;
	private final Configuration configuration;
	private boolean verbose = DEFAULT_VERBOSE;
	private MultiMessageExpectation multi;

	public LockstepEndpoint(final InetSocketAddress destination, Configuration configuration) {

		this.destination = destination;
		this.configuration = configuration;
		this.storage = new HashMap<String, Object>();
		this.incoming = new LinkedBlockingQueue<RawData>();
		this.connector = new UDPConnector(TestTools.LOCALHOST_EPHEMERAL, configuration);
		this.connector.setRawDataReceiver(new RawDataChannel() {

			public void receiveData(RawData raw) {
				incoming.offer(raw);
			}
		});
		this.serializer = new UdpDataSerializer();
		this.parser = new UdpDataParser();

		try {
			connector.start();
			// Thread.sleep(100);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public LockstepEndpoint(final LockstepEndpoint previousEndpoint) {
		this(previousEndpoint.destination, previousEndpoint.configuration);
		storage.putAll(previousEndpoint.storage);
	}

	public void destroy() {
		if (connector != null) {
			connector.destroy();
		}
	}

	public void print(String text) {
		if (verbose) {
			LOGGER.info("{}", text);
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

	public InetSocketAddress getSocketAddress() {
		return connector.getAddress();
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
			if (item instanceof MidUsage) {
				// newMID
				return ((MidUsage) item).currentMID;
			}
			throw new NoSuchElementException("Variable '" + var + "' is no MID (" + item.getClass() + ")");
		}
		throw new NoSuchElementException("No variable '" + var + "'");
	}

	/**
	 * Get token from stored values.
	 * 
	 * The token may be stored either by
	 * {@link MessageExpectation#storeToken(String)} or
	 * {@link MessageExpectation#storeBoth(String)}.
	 * 
	 * @param var name of variable
	 * @return token
	 * @throws NoSuchElementException, if nothing so stored under the name, or
	 *             the item doesn't contain a token.
	 */
	public Token getToken(String var) {
		Object item = storage.get(var);
		if (null != item) {
			if (item instanceof Token) {
				// saveToken
				return (Token) item;
			}
			if (item instanceof Object[]) {
				// saveBoth
				Object[] items = (Object[]) item;
				return (Token) items[1];
			}
			throw new NoSuchElementException("Variable '" + var + "' is no token (" + item.getClass() + ")");
		}
		throw new NoSuchElementException("No variable '" + var + "'");
	}

	public MultiMessageExpectation startMultiExpectation() {
		multi = new MultiMessageExpectation();
		return multi;
	}

	public void goMultiExpectation() throws Exception {
		assertNotNull("multi expectations not started!", multi);
		multi.go();
		multi = null;
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

	public ResponseExpectation expectResponse(Type type, ResponseCode code, Token token, int mid) {
		return expectResponse().type(type).code(code).token(token).mid(mid);
	}

	public ResponseExpectation expectSeparateResponse(Type type, ResponseCode code, Token token) {
		return expectResponse().type(type).code(code).token(token);
	}

	public EmptyMessageExpectation expectEmpty(Type type, int mid) {
		return new EmptyMessageExpectation(type, mid);
	}

	public RequestProperty sendRequest(Type type, Code code, Token token, int mid) {
		if (type == null) {
			throw new NullPointerException();
		}
		if (code == null) {
			throw new NullPointerException();
		}
		if (token == null) {
			throw new NullPointerException();
		}
		if (mid < 0 || mid > Message.MAX_MID) {
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
		InetSocketAddress address = raw.getEndpointContext().getPeerAddress();
		if (address.getAddress() == null || address.getPort() == 0) {
			throw new RuntimeException("Message has no destination address/port");
		}
		connector.send(raw);
	}

	public void setDestination(InetSocketAddress destination) {
		this.destination = destination;
	}

	/**
	 * Receive next expected message.
	 * 
	 * Apply smart deduplication based on {@link #lastIncomingMessage} and the
	 * MID, if the repeated MID is not expected. If no next message arrives,
	 * reports an assert.
	 * 
	 * <pre>
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
	 * </pre>
	 * 
	 * MID expectations are based on {@link MessageExpectation#mid(int)},
	 * {@link MessageExpectation#sameMID(String)} or
	 * {@link MessageExpectation#sameBoth(String)}.
	 * 
	 * @param midExpectation MID expectation
	 * @return next received message
	 * @throws InterruptedException if waiting for message is interrupted.
	 */
	public Message receiveNextExpectedMessage(MidExpectation midExpectation) throws InterruptedException {
		while (true) {
			Message msg = receiveNextMessage(2, TimeUnit.SECONDS);
			assertNotNull("did not receive message within expected time frame (2 secs)", msg);

			if (null != midExpectation && null != lastIncomingMessage && lastIncomingMessage.getMID() == msg.getMID()
					&& lastIncomingMessage.getType() == msg.getType() && !midExpectation.expectMID(msg)) {
				// received message with same MID but not expected
				// => discard message!
				print("discarding duplicate message: " + msg);
			} else {
				lastIncomingMessage = msg;
				return msg;
			}
		}
	}

	/**
	 * Receive next message.
	 * 
	 * @param timeout timeout for waiting for a message
	 * @param unit timeunit for waiting for a message
	 * @return received Message, or {@code null}, if no message arrived in time.
	 * @throws InterruptedException if waiting for message is interrupted.
	 */
	public Message receiveNextMessage(int timeout, TimeUnit unit) throws InterruptedException {
		RawData raw = incoming.poll(timeout, unit); // or take()?
		if (raw != null) {
			return parser.parseMessage(raw);
		}
		return null;
	}

	private static class MidUsage {

		Set<Integer> usedMIDs = new HashSet<Integer>();
		int currentMID;

		private void add(int mid) {
			usedMIDs.add(mid);
			currentMID = mid;
		}
	}

	public abstract class MessageExpectation implements Action {

		/**
		 * List of MID expectation. Used for smart deduplication.
		 */
		private List<MidExpectation> midExpectations = new LinkedList<MidExpectation>();
		private List<Expectation<Message>> expectations = new LinkedList<Expectation<Message>>();

		public MessageExpectation mid(final int mid) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					assertEquals("Wrong MID:", mid, message.getMID());
					print("Correct MID: " + mid);
				}

				public String toString() {
					return "Expected MID: " + mid;
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

		/**
		 * Check, if the MID stored under var is the same as the MID of the
		 * message. The MID may be stored either by {@link #storeMID(String)},
		 * {@link #storeBoth(String)}, or {@link #newMID(String)}.
		 * 
		 * Provides a fluent API to chain expectations.
		 * 
		 * @param var variable name with the stored MID
		 * @return this for fluent API
		 */
		public MessageExpectation sameMID(final String var) {
			expectations.add(new Expectation<Message>() {

				@Override
				public void check(Message message) {
					int expected = getMID(var);
					assertEquals("Wrong MID:", expected, message.getMID());
					print("Correct MID: " + expected);
				}

				public String toString() {
					int expected = getMID(var);
					return "Expected MID: " + expected;
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
					MidUsage usage = (MidUsage) storage.get(var);
					if (usage == null) {
						usage = new MidUsage();
					}
					if (!usage.usedMIDs.isEmpty()) {
						assertFalse("MID: " + mid + " is not new! " + usage.usedMIDs, usage.usedMIDs.contains(mid));
					}
					usage.add(mid);
					storage.put(var, usage);
				}

				@Override
				public String toString() {
					@SuppressWarnings("unchecked")
					Set<Integer> usedMIDs = (Set<Integer>) storage.get(var);
					return "Expected new MID, not " + usedMIDs;
				}
			});
			return this;
		}

		public MessageExpectation type(final Type... types) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					Type type = message.getType();
					assertTrue("Unexpected type: " + type + ", expected: " + Arrays.toString(types),
							Arrays.asList(types).contains(type));
				}

				public String toString() {
					if (types.length == 1) {
						return "Expected type: " + types[0];
					} else {
						return "Expected types: " + Arrays.toString(types);
					}
				}
			});
			return this;
		}

		public MessageExpectation token(final Token token) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					assertEquals("Wrong token:", token, message.getToken());
					print("Correct token: " + token.getAsString());
				}

				public String toString() {
					return "Expected token: " + token.getAsString();
				}
			});
			return this;
		}

		/**
		 * Check, if the token stored under var is the same as the token of the
		 * message. The token may be stored either by {@link #storeToken(String)} or
		 * {@link #storeBoth(String)}.
		 * 
		 * Provides a fluent API to chain expectations.
		 * 
		 * @param var variable name with the stored token
		 * @return this for fluent API
		 */
		public MessageExpectation sameToken(final String var) {
			expectations.add(new Expectation<Message>() {

				@Override
				public void check(Message message) {
					Token expected = getToken(var);
					assertEquals("Wrong token:", expected, message.getToken());
					print("Correct token: " + expected.getAsString());
				}

				public String toString() {
					Token expected = getToken(var);
					return "Expected token: " + expected.getAsString();
				}
			});
			return this;
		}

		public MessageExpectation size1(final int expectedSize) {
			expectations.add(new Expectation<Message>() {

				@Override
				public void check(final Message message) {
					assertThat("Wrong size1", message.getOptions().getSize1(), is(expectedSize));
				}

				@Override
				public String toString() {
					return "Expected Size1 option: " + expectedSize;
				}
			});
			return this;
		}

		public MessageExpectation payload(final String payload) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					if (payload.isEmpty()) {
						assertEquals("Payload not expected, length: ", 0, message.getPayloadSize());
						print("Correct empty payload");
					} else {
						int expectedLength = payload.length();
						int actualLength = message.getPayloadSize();
						assertEquals("Wrong payload length: ", expectedLength, actualLength);
						assertEquals("Wrong payload:", payload, message.getPayloadString());
						print("Correct payload (" + actualLength + " bytes):" + System.lineSeparator()
								+ message.getPayloadString());
					}
				}

				public String toString() {
					if (payload.isEmpty()) {
						return "Expected no payload";
					} else {
						return "Expected payload: '" + payload + "'";
					}
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
					assertTrue("No Block1 option:", message.getOptions().hasBlock1());
					BlockOption block1 = message.getOptions().getBlock1();
					assertEquals("Wrong Block1 num:", num, block1.getNum());
					assertEquals("Wrong Block1 m:", m, block1.isM());
					assertEquals("Wrong Block1 size:", size, block1.getSize());
					print("Correct Block1 option: " + block1);
				}

				public String toString() {
					BlockOption option = new BlockOption(BlockOption.size2Szx(size), m, num);
					return "Expected Block1 option: " + option;
				}
			});
			return this;
		}

		public MessageExpectation block2(final int num, final boolean m, final int size) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					assertTrue("No Block2 option:", message.getOptions().hasBlock2());
					BlockOption block2 = message.getOptions().getBlock2();
					assertEquals("Wrong Block2 num:", num, block2.getNum());
					assertEquals("Wrong Block2 m:", m, block2.isM());
					assertEquals("Wrong Block2 size:", size, block2.getSize());
					print("Correct Block2 option: " + block2);
				}

				public String toString() {
					BlockOption option = new BlockOption(BlockOption.size2Szx(size), m, num);
					return "Expected Block2 option: " + option;
				}
			});
			return this;
		}

		public MessageExpectation observe(final int observe) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					assertTrue("No observe option:", message.getOptions().hasObserve());
					int actual = message.getOptions().getObserve();
					assertEquals("Wrong observe sequence number:", observe, actual);
					print("Correct observe sequence number: " + observe);
				}

				public String toString() {
					return "Expected observe sequence number: " + observe;
				}
			});
			return this;
		}

		public MessageExpectation hasObserve() {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					assertTrue("No observe option:", message.getOptions().hasObserve());
					print("Has observe option");
				}

				public String toString() {
					return "Expected observe option";
				}
			});
			return this;
		}

		public MessageExpectation hasEtag(final byte[] etag) {

			expectations.add(new Expectation<Message>() {

				@Override
				public void check(final Message message) {
					assertThat(message.getOptions().getETags(), hasItem(etag));
				}

				@Override
				public String toString() {
					return String.format("Expected etag: %s", Utils.toHexString(etag));
				}
			});
			return this;
		}

		@Deprecated
		public MessageExpectation noOption(final int... numbers) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					List<Option> options = message.getOptions().asSortedList();
					for (Option option : options) {
						for (int n : numbers) {
							if (option.getNumber() == n) {
								fail("Must not have option number " + n + " but has " + option);
							}
						}
					}
				}

				public String toString() {
					StringBuilder result = new StringBuilder("Expected no options: [");
					if (0 < numbers.length) {
						final int end = numbers.length - 1;
						int index = 0;
						for (; index < end; ++index) {
							result.append(getOption(numbers[index])).append(",");
						}
						result.append(getOption(numbers[index]));
					}
					result.append(']');
					return result.toString();
				}

				private String getOption(int optionNumber) {
					OptionDefinition definition = StandardOptionRegistry.getDefaultOptionRegistry().getDefinitionByNumber(optionNumber);
					if (definition != null) {
						return definition.toString();
					} else {
						return String.format("Unknown (%d)", optionNumber);
					}
				}
			});
			return this;
		}

		public MessageExpectation noOption(final OptionDefinition... definitions) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					List<Option> options = message.getOptions().asSortedList();
					for (Option option : options) {
						for (OptionDefinition definition : definitions) {
							if (definition.equals(option.getDefinition())) {
								fail("Must not have option " + definition + " but has " + option);
							}
						}
					}
				}

				public String toString() {
					StringBuilder result = new StringBuilder("Expected no options: [");
					if (0 < definitions.length) {
						final int end = definitions.length - 1;
						int index = 0;
						for (; index < end; ++index) {
							result.append(definitions[index]).append(",");
						}
						result.append(definitions[index]);
					}
					result.append(']');
					return result.toString();
				}
			});
			return this;
		}

		public MessageExpectation storeMID(final String var) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					print("store " + var + ":=" + message.getMID());
					storage.put(var, message.getMID());
				}

				public String toString() {
					return "";
				}
			});
			return this;
		}

		public MessageExpectation storeToken(final String var) {
			expectations.add(new Expectation<Message>() {

				public void check(Message message) {
					print("store " + var + ":=" + message.getToken());
					storage.put(var, message.getToken());
				}

				public String toString() {
					return "";
				}
			});
			return this;
		}

		public MessageExpectation storeBoth(final String var) {
			expectations.add(new Expectation<Message>() {

				public void check(final Message message) {
					print("store " + var + ":=" + message.getToken() + "," + message.getMID());
					Object[] pair = new Object[2];
					pair[0] = message.getMID();
					pair[1] = message.getToken();
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
					assertEquals("Wrong MID:", pair[0], message.getMID());
					assertEquals("Wrong token:", pair[1], message.getToken());
					print("Correct MID: " + message.getMID() + " and token: " + message.getTokenString());
				}

				public String toString() {
					Object[] pair = (Object[]) storage.get(var);
					return "Expected MID: " + pair[0] + " and token " + ((Token) pair[1]).getAsString();
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

		@Override
		public void go() throws Exception {
			if (null != multi) {
				add(multi);
				return;
			}

			Message msg = receiveNextExpectedMessage(new MidExpectation() {

				@Override
				public boolean expectMID(Message message) {
					return MessageExpectation.this.expectMID(message);
				}
			});

			go(msg);
		}

		@Override
		public void go(TimeAssume assume) throws Exception {
			try {
				go();
			} catch (AssumptionViolatedException ex) {
				throw ex;
			} catch (Error ex) {
				if (assume.inTime()) {
					throw ex;
				} else {
					throw new AssumptionViolatedException("assumed time expired!", ex);
				}
			} catch (Exception ex) {
				if (assume.inTime()) {
					throw ex;
				} else {
					throw new AssumptionViolatedException("assumed time expired!", ex);
				}
			}
		}

		public String toString() {
			StringBuilder result = new StringBuilder("{");
			for (Expectation<Message> expectation : expectations) {
				String info = expectation.toString();
				if (!info.isEmpty()) {
					result.append(info).append(",");
				}
			}
			int end = result.length() - 1;
			if (0 <= end && ',' == result.charAt(end)) {
				result.setLength(end);
			}
			result.append("}");
			return result.toString();
		}

		public abstract void go(Message msg) throws Exception;

		public abstract void add(MultiMessageExpectation multi);
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
		public RequestExpectation token(final Token token) {
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
		public RequestExpectation hasEtag(final byte[] etag) {
			super.hasEtag(etag);
			return this;
		}

		@Deprecated
		@Override
		public RequestExpectation noOption(final int... numbers) {
			super.noOption(numbers);
			return this;
		}

		@Override
		public RequestExpectation noOption(final OptionDefinition... definitions) {
			super.noOption(definitions);
			return this;
		}

		@Override
		public RequestExpectation storeMID(final String var) {
			super.storeMID(var);
			return this;
		}

		@Override
		public RequestExpectation sameMID(final String var) {
			super.sameMID(var);
			return this;
		}

		@Override
		public RequestExpectation storeToken(final String var) {
			super.storeToken(var);
			return this;
		}

		@Override
		public RequestExpectation sameToken(final String var) {
			super.sameToken(var);
			return this;
		}

		@Override
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
					assertEquals(code, request.getCode());
					print("Correct code: " + code + " (" + code.value + ")");
				}
			});
			return this;
		}

		public RequestExpectation path(final String path) {
			expectations.add(new Expectation<Request>() {

				public void check(Request request) {
					assertEquals(path, request.getOptions().getUriPathString());
					print("Correct URI path: " + path);
				}
			});
			return this;
		}

		@Override
		public RequestExpectation size1(final int expectedSize) {
			super.size1(expectedSize);
			return this;
		}

		public void check(Request request) {
			super.check(request);
			for (Expectation<Request> expectation : expectations) {
				expectation.check(request);
			}
		}

		@Override
		public void go(Message msg) throws Exception {
			if (CoAP.isRequest(msg.getRawCode())) {
				check((Request) msg);
			} else {
				fail("Expected request for " + this + ", but received " + msg);
			}
		}

		@Override
		public void add(MultiMessageExpectation multi) {
			multi.add(this);
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
		public ResponseExpectation token(final Token token) {
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
		public ResponseExpectation hasObserve() {
			super.hasObserve();
			return this;
		}

		@Override
		public ResponseExpectation hasEtag(final byte[] etag) {
			super.hasEtag(etag);
			return this;
		}

		@Override
		public MessageExpectation size1(final int expectedSize) {
			super.size1(expectedSize);
			return this;
		}

		public ResponseExpectation size2(final int expectedSize) {
			expectations.add(new Expectation<Response>() {

				@Override
				public void check(final Response response) {
					assertThat("Wrong size2", response.getOptions().getSize2(), is(expectedSize));
				}

				@Override
				public String toString() {
					return "Expected Size2 option: " + expectedSize;
				}
			});
			return this;
		}

		@Deprecated
		@Override
		public ResponseExpectation noOption(final int... numbers) {
			super.noOption(numbers);
			return this;
		}

		@Override
		public ResponseExpectation noOption(final OptionDefinition... definitions) {
			super.noOption(definitions);
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
					assertEquals(code, response.getCode());
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
					assertTrue("Has no observe option", response.getOptions().hasObserve());
					storage.put(key, response.getOptions().getObserve());
				}
			});
			return this;
		}

		public ResponseExpectation sameObserve(final String var) {
			expectations.add(new Expectation<Response>() {

				@Override
				public void check(final Response response) {
					assertTrue("Response has no observer", response.getOptions().hasObserve());
					Object obj = storage.get(var);
					assertThat("Object stored under " + var + " is not an observe option", obj, is(instanceOf(Integer.class)));
					assertThat("Response contains wrong observe option", (Integer) obj,
							is(response.getOptions().getObserve()));
				}
			});
			return this;
		}

		public ResponseExpectation storeETag(final String var) {
			expectations.add(new Expectation<Response>() {

				@Override
				public void check(final Response response) {
					assertTrue("Response has no ETag", response.getOptions().getETagCount() > 0);
					storage.put(var, response.getOptions().getETags().get(0));
				}
			});
			return this;
		}

		public ResponseExpectation sameETag(final String var) {
			expectations.add(new Expectation<Response>() {

				@Override
				public void check(final Response response) {
					assertTrue("Response has no ETag", response.getOptions().getETagCount() > 0);
					Object obj = storage.get(var);
					assertThat("Object stored under " + var + " is not an ETag", obj, is(instanceOf(byte[].class)));
					assertThat("Response contains wrong ETag", (byte[]) obj,
							is(response.getOptions().getETags().get(0)));
				}
			});
			return this;
		}

		public ResponseExpectation newerObserve(final String key) {
			expectations.add(new Expectation<Response>() {

				public void check(Response response) {
					assertTrue("Has no observe option", response.getOptions().hasObserve());
					Object value = storage.get(key);
					if (value == null) {
						throw new IllegalArgumentException("Key " + key + " not found");
					}
					int V1 = (Integer) value;
					int V2 = response.getOptions().getObserve();
					boolean fresh = V1 < V2 && V2 - V1 < 1 << 23 || V1 > V2 && V1 - V2 > 1 << 23;
					assertTrue("Was not a fresh notification. Last obs=" + V1 + ", new=" + V2, fresh);
				}
			});
			return this;
		}

		public ResponseExpectation checkObs(String former, String next) {
			newerObserve(former);
			storeObserve(next);
			return this;
		}

		public ResponseExpectation loadObserve(final String key) {
			expectations.add(new Expectation<Response>() {

				public void check(Response response) {
					assertTrue("No observe option:", response.getOptions().hasObserve());
					int expected = (Integer) storage.get(key);
					int actual = response.getOptions().getObserve();
					assertEquals("Wrong observe sequence number:", expected, actual);
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

		@Override
		public void go(Message msg) throws Exception {
			if (CoAP.isResponse(msg.getRawCode())) {
				check((Response) msg);
			} else {
				fail("Expected response for " + this + ", but received " + msg);
			}
		}

		@Override
		public void add(MultiMessageExpectation multi) {
			multi.add(this);
		}

	}

	public class EmptyMessageExpectation extends MessageExpectation {

		public EmptyMessageExpectation(Type type, int mid) {
			super();
			type(type).mid(mid);
		}

		public EmptyMessageExpectation(Type type, String midVar) {
			super();
			type(type).sameMID(midVar);
		}

		@Override
		public void go(Message msg) throws Exception {
			if (CoAP.isEmptyMessage(msg.getRawCode())) {
				check(msg);
			} else {
				fail("Expected empty message for " + this + ", but received " + msg);
			}
		}

		@Override
		public void add(MultiMessageExpectation multi) {
			multi.add(this);
		}
	}

	public class MultiMessageExpectation implements Action {

		private int counter;
		private EmptyMessageExpectation emptyExpectation;
		private RequestExpectation requestExpectation;
		private ResponseExpectation responseExpectation;

		public MultiMessageExpectation add(final EmptyMessageExpectation emptyExpectation) {
			if (null == emptyExpectation) {
				throw new IllegalArgumentException("no empty message expectation!");
			}
			if (null != this.emptyExpectation) {
				throw new IllegalStateException("empty message expectation already set!");
			}
			this.emptyExpectation = emptyExpectation;
			this.counter++;
			return this;
		}

		public MultiMessageExpectation add(final RequestExpectation requestExpectation) {
			if (null == requestExpectation) {
				throw new IllegalStateException("no request expectation!");
			}
			if (null != this.requestExpectation) {
				throw new IllegalStateException("request expectation already set!");
			}
			this.requestExpectation = requestExpectation;
			this.counter++;
			return this;
		}

		public MultiMessageExpectation add(final ResponseExpectation responseExpectation) {
			if (null == responseExpectation) {
				throw new IllegalStateException("no response expectation!");
			}
			if (null != this.responseExpectation) {
				throw new IllegalStateException("response expectation already set!");
			}
			this.responseExpectation = responseExpectation;
			this.counter++;
			return this;
		}

		public boolean expectMID(Message message) {
			int rawCode = message.getRawCode();
			if (CoAP.isEmptyMessage(rawCode)) {
				if (null != emptyExpectation) {
					return emptyExpectation.expectMID(message);
				}
			} else if (CoAP.isRequest(rawCode)) {
				if (null != requestExpectation) {
					return requestExpectation.expectMID(message);
				}
			} else if (CoAP.isResponse(rawCode)) {
				if (null != responseExpectation) {
					return responseExpectation.expectMID(message);
				}
			}
			return false;
		}

		@Override
		public void go() throws Exception {
			assertTrue("No expectations added!)", 0 < counter);
			while (0 < counter) {
				Message msg = receiveNextExpectedMessage(new MidExpectation() {

					@Override
					public boolean expectMID(Message message) {
						return MultiMessageExpectation.this.expectMID(message);
					}
				});
				int rawCode = msg.getRawCode();
				if (CoAP.isEmptyMessage(rawCode)) {
					if (null != emptyExpectation) {
						emptyExpectation.go(msg);
						emptyExpectation = null;
						--counter;
					} else {
						fail("No empty message expected " + msg);
					}
				} else if (CoAP.isRequest(rawCode)) {
					if (null != requestExpectation) {
						requestExpectation.go(msg);
						requestExpectation = null;
						--counter;
					} else {
						fail("No request expected " + msg);
					}
				} else if (CoAP.isResponse(rawCode)) {
					if (null != responseExpectation) {
						responseExpectation.go(msg);
						responseExpectation = null;
						--counter;
					} else {
						fail("No response expected " + msg);
					}
				}
			}
		}

		@Override
		public void go(TimeAssume assume) throws Exception {
			try {
				go();
			} catch (AssumptionViolatedException ex) {
				throw ex;
			} catch (Error ex) {
				if (assume.inTime()) {
					throw ex;
				} else {
					throw new AssumptionViolatedException("assumed time expired!", ex);
				}
			} catch (Exception ex) {
				if (assume.inTime()) {
					throw ex;
				} else {
					throw new AssumptionViolatedException("assumed time expired!", ex);
				}
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
		private Token token;
		private int mid;

		public MessageProperty(Type type) {
			this.type = type;
		}

		public MessageProperty(Type type, Token token, int mid) {
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

		public MessageProperty payload(final String payload, final int from, final int to) {
			properties.add(new Property<Message>() {

				public void set(final Message message) {
					message.setPayload(payload.substring(from, to));
				}
			});
			return this;
		}

		public MessageProperty mid(final int mid) {
			this.mid = mid;
			return this;
		}
		
		public MessageProperty token(final Token token) {
			this.token = token;
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

		public MessageProperty size1(final int size) {
			properties.add(new Property<Message>() {

				@Override
				public void set(final Message message) {
					message.getOptions().setSize1(size);
				}
			});
			return this;
		}

		public MessageProperty size2(final int size) {
			properties.add(new Property<Message>() {

				@Override
				public void set(final Message message) {
					message.getOptions().setSize2(size);
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

		public MessageProperty etag(final byte[] tag) {
			properties.add(new Property<Message>() {

				@Override
				public void set(final Message message) {
					message.getOptions().addETag(tag);
				}
			});
			return this;
		}

		public MessageProperty loadMID(final String var) {
			properties.add(new Property<Message>() {

				public void set(Message message) {
					int mid = getMID(var);
					message.setMID(mid);
				}
			});
			return this;
		}

		public MessageProperty loadToken(final String var) {
			properties.add(new Property<Message>() {

				public void set(Message message) {
					Token tok = getToken(var);
					message.setToken(tok);
				}
			});
			return this;
		}
	}

	public class EmptyMessageProperty extends MessageProperty {

		public EmptyMessageProperty(Type type, int mid) {
			super(type, Token.EMPTY, mid);
		}

		public EmptyMessageProperty(Type type, String midVar) {
			super(type);
			super.loadMID(midVar);
		}

		@Override
		public void go() {
			EmptyMessage message = new EmptyMessage(null);
			setProperties(message);
			EndpointContext context = new AddressEndpointContext(destination);
			message.setDestinationContext(context);
			RawData raw = serializer.serializeEmptyMessage(message, null);
			send(raw);
		}

		@Override
		public void go(TimeAssume assume) throws Exception {
			go();
		}
	}

	public class RequestProperty extends MessageProperty {

		private List<Property<Request>> properties = new LinkedList<LockstepEndpoint.Property<Request>>();

		private Code code;

		public RequestProperty(Type type, Code code, Token token, int mid) {
			super(type, token, mid);
			this.code = code;
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
		public RequestProperty size1(int size) {
			super.size1(size);
			return this;
		}

		@Override
		public RequestProperty size2(int size) {
			super.size2(size);
			return this;
		}

		@Override
		public RequestProperty observe(final int observe) {
			super.observe(observe);
			return this;
		}

		@Override
		public RequestProperty etag(final byte[] tag) {
			super.etag(tag);
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

		@Override
		public RequestProperty payload(final String payload, final int from, final int to) {
			super.payload(payload, from, to);
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

		public RequestProperty loadETag(final String var) {
			properties.add(new Property<Request>() {

				public void set(final Request request) {
					Object obj = storage.get(var);
					assertThat("Object stored under variable " + var + " is not a byte array", obj,
							is(instanceOf(byte[].class)));
					request.getOptions().addETag((byte[]) obj);
				}
			});
			return this;
		}

		public void setProperties(Request request) {
			super.setProperties(request);
			for (Property<Request> property : properties) {
				property.set(request);
			}
		}

		@Override
		public void go() {
			Request request = new Request(code);
			setProperties(request);
			EndpointContext context = new AddressEndpointContext(destination);
			request.setDestinationContext(context);
			RawData raw = serializer.serializeRequest(request);
			send(raw);
		}

		@Override
		public void go(TimeAssume assume) throws Exception {
			go();
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
		public ResponseProperty token(final Token token) {
			super.token(token);
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
		public ResponseProperty size1(int size) {
			super.size1(size);
			return this;
		}

		@Override
		public ResponseProperty size2(int size) {
			super.size2(size);
			return this;
		}

		@Override
		public ResponseProperty observe(final int observe) {
			super.observe(observe);
			return this;
		}

		@Override
		public ResponseProperty etag(final byte[] tag) {
			super.etag(tag);
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

		@Override
		public ResponseProperty payload(final String payload, final int from, final int to) {
			super.payload(payload, from, to);
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
					response.setToken((Token) pair[1]);
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
			setProperties(response);
			EndpointContext context = new AddressEndpointContext(destination);
			response.setDestinationContext(context);
			RawData raw = serializer.serializeResponse(response, null);
			send(raw);
		}

		@Override
		public void go(TimeAssume assume) throws Exception {
			go();
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

		public void go(TimeAssume assume) throws Exception;
	}

	public static interface MidExpectation {

		public boolean expectMID(Message message);
	}

}
