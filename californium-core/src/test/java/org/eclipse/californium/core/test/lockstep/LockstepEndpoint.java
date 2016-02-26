/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use static reference to Serializer
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;

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

	public static boolean DEFAULT_VERBOSE = false;
	
	private UDPConnector connector;
	private InetSocketAddress destination;
	private LinkedBlockingQueue<RawData> incoming;
	
	private HashMap<String, Object> storage;
	
	private boolean verbose = DEFAULT_VERBOSE;

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
		if (type == null) throw new NullPointerException();
		if (code == null) throw new NullPointerException();
		if (token == null) throw new NullPointerException();
		if (mid < 0 || mid > (2<<16)-1) throw new RuntimeException();
		return new RequestProperty(type, code, token, mid);
	}
	
	public ResponseProperty sendResponse(Type type, ResponseCode code) {
		if (type == null) throw new NullPointerException();
		if (code == null) throw new NullPointerException();
		return new ResponseProperty(type, code);
	}
	
	public EmptyMessageProperty sendEmpty(Type type) {
		if (type == null) throw new NullPointerException();
		return sendEmpty(type, Message.NONE);
	}
	
	public EmptyMessageProperty sendEmpty(Type type, int mid) {
		return new EmptyMessageProperty(type, mid);
	}
	
	public void send(RawData raw) {
		if (raw.getAddress() == null || raw.getPort() == 0)
			throw new RuntimeException("Message has no destination address/port");
		
		connector.send(raw);
	}
	
	public void setDestination(InetSocketAddress destination) {
		this.destination = destination;
	}
	
	public abstract class MessageExpectation implements Action {
		
		private List<Expectation<Message>> expectations = new LinkedList<LockstepEndpoint.Expectation<Message>>();
		
		public MessageExpectation mid(final int mid) {
			expectations.add(new Expectation<Message>() {
				public void check(Message message) {
					Assert.assertEquals("Wrong MID:", mid, message.getMID());
					print("Correct MID: "+mid);
				}
			});
			return this;
		}
		
		public MessageExpectation loadMID(final String var) {
			expectations.add(new Expectation<Message>() {
				public void check(Message message) {
					int expected = (Integer) storage.get(var);
					Assert.assertEquals("Wrong MID:", expected, message.getMID());
					print("Correct MID: "+expected);
				}
			});
			return this;
		}

		public MessageExpectation type(final Type type) {
			expectations.add(new Expectation<Message>() {
				public void check(Message message) {
					Assert.assertEquals("Wrong type:", type, message.getType());
					print("Correct type: "+type);
				}
			});
			return this;
		}

		public MessageExpectation token(final byte[] token) {
			expectations.add(new Expectation<Message>() {
				public void check(Message message) {
					org.junit.Assert.assertArrayEquals("Wrong token:", token, message.getToken());
					print("Correct token: "+Utils.toHexString(token));
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
					print("Correct payload ("+actualLength+" bytes):\n"+message.getPayloadString());
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
					print("Correct Block1 option: "+block1);
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
					print("Correct Block2 option: "+block2);
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
					print("Correct observe sequence number: "+observe);
				}
			});
			return this;
		}
		
		public MessageExpectation noOption(final int... numbers) {
			expectations.add(new Expectation<Message>() {
				public void check(Message message) {
					List<Option> options = message.getOptions().asSortedList();
					for (Option option:options) {
						for (int n:numbers) {
							if (option.getNumber() == n) {
								Assert.assertTrue("Must not have option number "+n+" but has", false);
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
		
		public void check(Message message) {
			for (Expectation<Message> expectation:expectations)
				expectation.check(message);
		}
	}
	
	public class RequestExpectation extends MessageExpectation {
		
		private List<Expectation<Request>> expectations = new LinkedList<LockstepEndpoint.Expectation<Request>>();
		
		@Override public RequestExpectation mid(final int mid) {
			super.mid(mid); return this;
		}

		@Override public RequestExpectation type(final Type type) {
			super.type(type); return this;
		}

		@Override public RequestExpectation token(final byte[] token) {
			super.token(token); return this;
		}

		@Override public RequestExpectation payload(final String payload) {
			super.payload(payload); return this;
		}
		
		@Override public RequestExpectation payload(String payload, int from, int to) {
			super.payload(payload, from, to); return this;
		}
		
		@Override public RequestExpectation block1(final int num, final boolean m, final int size) {
			super.block1(num, m, size); return this;
		}
		
		@Override public RequestExpectation block2(final int num, final boolean m, final int size) {
			super.block2(num, m, size); return this;
		}
		
		@Override public RequestExpectation observe(final int observe) {
			super.observe(observe); return this;
		}

		@Override public RequestExpectation noOption(final int... numbers) {
			super.noOption(numbers); return this;
		}
		
		@Override public RequestExpectation storeMID(final String var) {
			super.storeMID(var); return this;
		}
		
		@Override public MessageExpectation storeToken(final String var) {
			super.storeToken(var); return this;
		}

		public RequestExpectation storeBoth(final String var) {
			expectations.add(new Expectation<Request>() {
				public void check(final Request request) {
					Object[] pair = new Object[2];
					pair[0] = request.getMID();
					pair[1] = request.getToken();
					storage.put(var, pair);
				}
			});
			return this;
		}
		
		public RequestExpectation code(final Code code) {
			expectations.add(new Expectation<Request>() {
				public void check(Request request) {
					Assert.assertEquals(code, request.getCode());
					print("Correct code: "+code+" ("+code.value+")");
				}
			});
			return this;
		}
		
		public RequestExpectation path(final String path) {
			expectations.add(new Expectation<Request>() {
				public void check(Request request) {
					Assert.assertEquals(path, request.getOptions().getUriPathString());
					print("Correct URI path: "+path);
				}
			});
			return this;
		}
		
		public void check(Request request) {
			super.check(request);
			for (Expectation<Request> expectation:expectations)
				expectation.check(request);
		}

		@Override 
		public void go() throws Exception {
			RawData raw = incoming.poll(2, TimeUnit.SECONDS); // or take()?
			Assert.assertNotNull("Did not receive a request (but nothing)", raw);
			DataParser parser = new DataParser(raw.getBytes());
			
			if (parser.isRequest()) {
				Request request = parser.parseRequest();
				request.setSource(raw.getAddress());
				request.setSourcePort(raw.getPort());
				check(request);
				
			} else {
				Assert.fail("Expected request but received " + parser);
			}
		}
	}

	public class ResponseExpectation extends MessageExpectation {
		
		private Response response;
		
		private List<Expectation<Response>> expectations = new LinkedList<LockstepEndpoint.Expectation<Response>>();
		
		@Override public ResponseExpectation mid(final int mid) {
			super.mid(mid); return this;
		}

		@Override public ResponseExpectation type(final Type type) {
			super.type(type); return this;
		}

		@Override public ResponseExpectation token(final byte[] token) {
			super.token(token); return this;
		}

		@Override public ResponseExpectation payload(final String payload) {
			super.payload(payload); return this;
		}
		
		@Override public ResponseExpectation payload(String payload, int from, int to) {
			super.payload(payload, from, to); return this;
		}
		
		@Override public ResponseExpectation block1(final int num, final boolean m, final int size) {
			super.block1(num, m, size); return this;
		}
		
		@Override public ResponseExpectation block2(final int num, final boolean m, final int size) {
			super.block2(num, m, size); return this;
		}
		
		@Override public ResponseExpectation observe(final int observe) {
			super.observe(observe); return this;
		}

		@Override public ResponseExpectation noOption(final int... numbers) {
			super.noOption(numbers); return this;
		}
		
		@Override public ResponseExpectation storeMID(final String var) {
			super.storeMID(var); return this;
		}
		
		@Override public ResponseExpectation loadMID(final String var) {
			super.loadMID(var); return this;
		}
		
		public ResponseExpectation code(final ResponseCode code) {
			expectations.add(new Expectation<Response>() {
				public void check(Response response) {
					Assert.assertEquals(code, response.getCode());
					print("Correct code: "+code+" ("+code.value+")");
				}
			});
			return this;
		}
		
		public ResponseExpectation responseType(final String key, final Type... acceptable) {
			expectations.add(new Expectation<Response>() {
				public void check(Response response) {
					Type type = response.getType();
					Assert.assertTrue("Unexpected type: "+type+", expected: "+Arrays.toString(acceptable),
							Arrays.asList(acceptable).contains(type));
					print("Correct type: "+type);
					if (key != null)
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
					if (value == null) throw new IllegalArgumentException("Key "+key+" not found");
					int V1 = (Integer) value;
					int V2 = response.getOptions().getObserve();
					boolean fresh = V1 < V2 && V2 - V1 < 1<<23 || V1 > V2 && V1 - V2 > 1<<23;
					Assert.assertTrue("Was not a fresh notification. Last obs="+V1+", new="+V2, fresh);
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
					print("Correct observe sequence number: "+expected);
				}
			});
			return this;
		}
		
		public void check(Response response) {
			super.check(response);
			for (Expectation<Response> expectation:expectations)
				expectation.check(response);
		}

		public void go() throws Exception {
			RawData raw = incoming.poll(2, TimeUnit.SECONDS); // or take() ?
			Assert.assertNotNull("Did not receive a response (but nothing)", raw);
			DataParser parser = new DataParser(raw.getBytes());
			
			if (parser.isResponse()) {
				this.response = parser.parseResponse();
				response.setSource(raw.getAddress());
				response.setSourcePort(raw.getPort());
				check(response);
				
			} else {
				Assert.fail("Expected response but received " + parser);
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
			RawData raw = incoming.poll(2, TimeUnit.SECONDS); // or take() ?
			Assert.assertNotNull("Did not receive an empty message (but nothing)", raw);
			DataParser parser = new DataParser(raw.getBytes());
			if (parser.isEmpty()) {
				EmptyMessage empty = parser.parseEmptyMessage();
				empty.setSource(raw.getAddress());
				empty.setSourcePort(raw.getPort());
				check(empty);
			} else {
				Assert.fail("Expected empty message but received " + parser);
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
			for (Property<Message> property:properties)
				property.set(message);
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

			RawData raw = Serializer.serialize(message);
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
		
		@Override public RequestProperty mid(final int mid) {
			super.mid(mid); return this;
		}
		
		@Override public RequestProperty block1(final int num, final boolean m, final int size) {
			super.block1(num, m, size); return this;
		}
		
		@Override public RequestProperty block2(final int num, final boolean m, final int size) {
			super.block2(num, m, size); return this;
		}
		
		@Override public RequestProperty observe(final int observe) {
			super.observe(observe); return this;
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
			for (Property<Request> property:properties)
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

			RawData raw = Serializer.serialize(request);
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
		
		@Override public ResponseProperty loadToken(final String var) {
			super.loadToken(var); return this;
		}

		@Override public ResponseProperty loadMID(final String var) {
			super.loadMID(var); return this;
		}

		@Override public ResponseProperty mid(final int mid) {
			super.mid(mid); return this;
		}

		@Override public ResponseProperty block1(final int num, final boolean m, final int size) {
			super.block1(num, m, size); return this;
		}

		@Override public ResponseProperty block2(final int num, final boolean m, final int size) {
			super.block2(num, m, size); return this;
		}
		
		@Override public ResponseProperty observe(final int observe) {
			super.observe(observe); return this;
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
					if (pair == null)
						throw new NullPointerException("Did not find MID and token for variable "+var+". Did you forgot a go()?");
					response.setMID((Integer) pair[0]);
					response.setToken((byte[]) pair[1]);
				}
			});
			return this;
		}
		
		public void setProperties(Response response) {
			super.setProperties(response);
			for (Property<Response> property:properties)
				property.set(response);
		}

		@Override
		public void go() {
			Response response = new Response(code);
			if (destination != null) {
				response.setDestination(destination.getAddress());
				response.setDestinationPort(destination.getPort());
			}
			setProperties(response);

			RawData raw = Serializer.serialize(response);
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
}
