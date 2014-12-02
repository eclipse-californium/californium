/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.EndpointManager.ClientMessageDeliverer;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.Serializer;
import org.eclipse.californium.core.network.stack.BlockwiseLayer;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.core.network.stack.ObserveLayer;
import org.eclipse.californium.core.network.stack.ReliabilityLayer;
import org.eclipse.californium.core.network.stack.TokenLayer;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.UDPConnector;


/**
 * Endpoint encapsulates the stack that executes the CoAP protocol. Endpoint
 * forwards incoming messages to a {@link MessageDeliverer}. The deliverer will
 * deliver requests to its destination resource. The resource sends the response
 * back over the same endpoint. The endpoint sends outgoing messages over a
 * connector. The connector encapsulates the transport protocol.
 * <p>
 * The CoAP Draft 18 describes an endpoint as: "A CoAP Endpoint is is identified
 * by transport layer multiplexing information that can include a UDP port
 * number and a security association." (draft-ietf-core-coap-14: 1.2)
 * <p>
 * The following diagram describes the structure of an endpoint. The endpoint
 * implements CoAP in layers. Incoming and outgoing messages always travel from
 * layer to layer. An {@link Exchange} represents the known state about the
 * exchange between a request and one or more corresponding responses. The
 * matcher remembers outgoing messages and matches incoming responses, acks and
 * rsts to them. MessageInterceptors receive every incoming and outgoing
 * message. By default, only one interceptor is used to log messages.
 * 
 * <pre>
 * +-----------------------+
 * |   {@link MessageDeliverer}    +--&gt; (Resource Tree)
 * +-------------A---------+
 *               |
 *             * A            
 * +-Endpoint--+-A---------+
 * |           v A         |  
 * |           v A         |  
 * | +---------v-+-------+ |  
 * | | Stack Top         | |  
 * | +-------------------+ |  
 * | | {@link TokenLayer}        | |
 * | +-------------------+ |  
 * | | {@link ObserveLayer}      | |
 * | +-------------------+ |  
 * | | {@link BlockwiseLayer}    | |
 * | +-------------------+ |  
 * | | {@link ReliabilityLayer}  | |
 * | +-------------------+ |  
 * | | Stack Bottom      | |  
 * | +--------+-+--------+ |  
 * |          v A          |  
 * |          v A          |  
 * |        {@link Matcher}        |
 * |          v A          |  
 * |   {@link MessageInterceptor}  |  
 * |          v A          |  
 * |          v A          |  
 * | +--------v-+--------+ |  
 * +-|     {@link Connector}     |-+
 *   +--------+-A--------+    
 *            v A             
 *            v A             
 *         (Network)
 * </pre>
 * <p>
 * The endpoint and its layers use an {@link ScheduledExecutorService} to
 * execute tasks, e.g., when a request arrives.
 */
public class CoAPEndpoint implements Endpoint {
	
	/** the logger. */
	private final static Logger LOGGER = Logger.getLogger(CoAPEndpoint.class.getCanonicalName());
	
	/** The stack of layers that make up the CoAP protocol */
	private final CoapStack coapstack;
	
	/** The connector over which the endpoint connects to the network */
	private final Connector connector;
	
	/** The configuration of this endpoint */
	private final NetworkConfig config;
	
	/** The executor to run tasks for this endpoint and its layers */
	private ScheduledExecutorService executor;
	
	/** Indicates if the endpoint has been started */
	private boolean started;
	
	/** The list of endpoint observers (has nothing to do with CoAP observe relations) */
	private List<EndpointObserver> observers = new ArrayList<EndpointObserver>(0);
	
	/** The list of interceptors */
	private List<MessageInterceptor> interceptors = new ArrayList<MessageInterceptor>(0);

	/** The matcher which matches incoming responses, akcs and rsts an exchange */
	private Matcher matcher;
	
	/** The serializer to serialize messages to bytes */
	private Serializer serializer;
	
	/**
	 * Instantiates a new endpoint with an ephemeral port.
	 */
	public CoAPEndpoint() {
		this(0);
	}
	
	/**
	 * Instantiates a new endpoint with the specified port
	 *
	 * @param port the port
	 */
	public CoAPEndpoint(int port) {
		this(new InetSocketAddress(port));
	}

	/**
	 * Instantiates a new endpoint with the specified address.
	 *
	 * @param address the address
	 */
	public CoAPEndpoint(InetSocketAddress address) {
		this(address, NetworkConfig.getStandard());
	}
	
	public CoAPEndpoint(NetworkConfig config) {
		this(new InetSocketAddress(0), config);
	}
	
	/**
	 * Instantiates a new endpoint with the specified port and configuration.
	 *
	 * @param address the address
	 */
	public CoAPEndpoint(int port, NetworkConfig config) {
		this(new InetSocketAddress(port), config);
	}
	
	/**
	 * Instantiates a new endpoint with the specified address and configuration.
	 *
	 * @param address the address
	 * @param config the configuration
	 */
	public CoAPEndpoint(InetSocketAddress address, NetworkConfig config) {
		this(createUDPConnector(address, config), config);
	}
	
	/**
	 * Instantiates a new endpoint with the specified connector and
	 * configuration.
	 *
	 * @param connector the connector
	 * @param config the config
	 */
	public CoAPEndpoint(Connector connector, NetworkConfig config) {
		this.config = config;
		this.connector = connector;
		this.serializer = new Serializer();
		this.matcher = new Matcher(config);		
		this.coapstack = new CoapStack(config, new OutboxImpl());
		this.connector.setRawDataReceiver(new InboxImpl());
	}
	
	/**
	 * Creates a new UDP connector.
	 *
	 * @param address the address
	 * @param config the configuration
	 * @return the connector
	 */
	private static Connector createUDPConnector(InetSocketAddress address, NetworkConfig config) {
		UDPConnector c = new UDPConnector(address);
		
		c.setReceiverThreadCount(config.getInt(NetworkConfig.Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT));
		c.setSenderThreadCount(config.getInt(NetworkConfig.Keys.NETWORK_STAGE_SENDER_THREAD_COUNT));
		
		c.setReceiveBufferSize(config.getInt(NetworkConfig.Keys.UDP_CONNECTOR_RECEIVE_BUFFER));
		c.setSendBufferSize(config.getInt(NetworkConfig.Keys.UDP_CONNECTOR_SEND_BUFFER));
		c.setLogPackets(config.getBoolean(NetworkConfig.Keys.UDP_CONNECTOR_LOG_PACKETS));
		c.setReceiverPacketSize(config.getInt(NetworkConfig.Keys.UDP_CONNECTOR_DATAGRAM_SIZE));
		
		return c;
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#start()
	 */
	@Override
	public synchronized void start() throws IOException {
		if (started) {
			LOGGER.log(Level.FINE, "Endpoint bound to " + getAddress().toString() + " is already started");
			return;
		}
		
		if (!this.coapstack.hasDeliverer())
			this.coapstack.setDeliverer(new ClientMessageDeliverer());
		
		if (this.executor == null) {
			LOGGER.config("Endpoint "+toString()+" requires an executor to start. Using default single-threaded daemon executor.");
			
			final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(new Utils.DaemonThreadFactory());
			setExecutor(executor);
			addObserver(new EndpointObserver() {
				public void started(Endpoint endpoint) { }
				public void stopped(Endpoint endpoint) { }
				public void destroyed(Endpoint endpoint) {
					executor.shutdown();
				}
			});
		}
		
		try {
			LOGGER.log(Level.INFO, "Starting Endpoint bound to " + getAddress());
			started = true;
			matcher.start();
			connector.start();
			for (EndpointObserver obs:observers)
				obs.started(this);
			startExecutor();
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, "Cannot start Endpoint at " + getAddress(), e);
			stop();
			throw e;
		}
	}
	
	/**
	 * Makes sure that the executor has started, i.e., a thread has been
	 * created. This is necessary for the server because it makes sure a
	 * non-daemon thread is running. Otherwise the program might find that only
	 * daemon threads are running and exit.
	 */
	private void startExecutor() {
		// Run a task that does nothing but make sure at least one thread of
		// the executor has started.
		executeTask(new Runnable() {
			public void run() { /* do nothing */ }
		});
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#stop()
	 */
	@Override
	public synchronized void stop() {
		if (!started) {
			LOGGER.log(Level.INFO, "Endpoint at address " + getAddress() + " is already stopped");
		} else {
			LOGGER.log(Level.INFO, "Stopping endpoint at address " + getAddress());
			started = false;
			connector.stop();
			matcher.stop();
			for (EndpointObserver obs:observers)
				obs.stopped(this);
			matcher.clear();
		}
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#destroy()
	 */
	@Override
	public synchronized void destroy() {
		LOGGER.log(Level.INFO, "Destroying endpoint at address " + getAddress());
		if (started)
			stop();
		connector.destroy();
		for (EndpointObserver obs:observers)
			obs.destroyed(this);
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#clear()
	 */
	@Override
	public void clear() {
		matcher.clear();
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#isStarted()
	 */
	@Override
	public boolean isStarted() {
		return started;
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#setExecutor(java.util.concurrent.ScheduledExecutorService)
	 */
	@Override
	public synchronized void setExecutor(ScheduledExecutorService executor) {
		this.executor = executor;
		this.coapstack.setExecutor(executor);
		this.matcher.setExecutor(executor);
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#addObserver(org.eclipse.californium.core.network.EndpointObserver)
	 */
	@Override
	public void addObserver(EndpointObserver obs) {
		observers.add(obs);
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#removeObserver(org.eclipse.californium.core.network.EndpointObserver)
	 */
	@Override
	public void removeObserver(EndpointObserver obs) {
		observers.remove(obs);
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#addInterceptor(org.eclipse.californium.core.network.MessageIntercepter)
	 */
	@Override
	public void addInterceptor(MessageInterceptor interceptor) {
		interceptors.add(interceptor);
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#removeInterceptor(org.eclipse.californium.core.network.MessageIntercepter)
	 */
	@Override
	public void removeInterceptor(MessageInterceptor interceptor) {
		interceptors.remove(interceptor);
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#getInterceptors()
	 */
	@Override
	public List<MessageInterceptor> getInterceptors() {
		return new ArrayList<MessageInterceptor>(interceptors);
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#sendRequest(org.eclipse.californium.core.coap.Request)
	 */
	@Override
	public void sendRequest(final Request request) {
		executor.execute(new Runnable() {
			public void run() {
				try {
					coapstack.sendRequest(request);
				} catch (Throwable t) {
					t.printStackTrace();
				}
			}
		});
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#sendResponse(org.eclipse.californium.core.network.Exchange, org.eclipse.californium.core.coap.Response)
	 */
	@Override
	public void sendResponse(final Exchange exchange, final Response response) {
		// TODO: If the currently executing thread is not a thread of the
		// executor, a new task on the executor should be created to send the
		// response. (Just uncomment this code)
//		executor.execute(new Runnable() {
//			public void run() {
//				try {
//					coapstack.sendResponse(exchange, response);
//				} catch (Exception e) {
//					e.printStackTrace();
//				}
//			}
//		});
		coapstack.sendResponse(exchange, response);
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#sendEmptyMessage(org.eclipse.californium.core.network.Exchange, org.eclipse.californium.core.coap.EmptyMessage)
	 */
	@Override
	public void sendEmptyMessage(final Exchange exchange, final EmptyMessage message) {
		executor.execute(new Runnable() {
			public void run() {
				try {
					coapstack.sendEmptyMessage(exchange, message);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#setMessageDeliverer(org.eclipse.californium.core.server.MessageDeliverer)
	 */
	@Override
	public void setMessageDeliverer(MessageDeliverer deliverer) {
		coapstack.setDeliverer(deliverer);
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#getAddress()
	 */
	@Override
	public InetSocketAddress getAddress() {
		return connector.getAddress();
	}

	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.network.Endpoint#getConfig()
	 */
	@Override
	public NetworkConfig getConfig() {
		return config;
	}

	/**
	 * The stack of layers uses this Outbox to send messages. The OutboxImpl
	 * will then give them to the matcher, the interceptors, and finally send
	 * them over the connector.
	 */
	private class OutboxImpl implements Outbox {
		
		@Override
		public void sendRequest(Exchange exchange, Request request) {
			matcher.sendRequest(exchange, request);
			
			/* 
			 * Logging here causes significant performance loss.
			 * If necessary, add an interceptor that logs the messages,
			 * e.g., the MessageTracer.
			 */
			
			for (MessageInterceptor interceptor:interceptors)
				interceptor.sendRequest(request);

			// MessageInterceptor might have canceled
			if (!request.isCanceled())
				connector.send(serializer.serialize(request));
		}

		@Override
		public void sendResponse(Exchange exchange, Response response) {
			matcher.sendResponse(exchange, response);
			
			/* 
			 * Logging here causes significant performance loss.
			 * If necessary, add an interceptor that logs the messages,
			 * e.g., the MessageTracer.
			 */
			
			for (MessageInterceptor interceptor:interceptors)
				interceptor.sendResponse(response);

			// MessageInterceptor might have canceled
			if (!response.isCanceled())
				connector.send(serializer.serialize(response));
		}

		@Override
		public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
			matcher.sendEmptyMessage(exchange, message);
			
			/* 
			 * Logging here causes significant performance loss.
			 * If necessary, add an interceptor that logs the messages,
			 * e.g., the MessageTracer.
			 */
			
			for (MessageInterceptor interceptor:interceptors)
				interceptor.sendEmptyMessage(message);

			// MessageInterceptor might have canceled
			if (!message.isCanceled())
				connector.send(serializer.serialize(message));
		}
	}
	
	/**
	 * The connector uses this channel to forward messages (in form of
	 * {@link RawData}) to the endpoint. The endpoint creates a new task to
	 * process the message. The task consists of invoking the matcher to look
	 * for an associated exchange and then forwards the message with the
	 * exchange to the stack of layers.
	 */
	private class InboxImpl implements RawDataChannel {

		@Override
		public void receiveData(final RawData raw) {
			if (raw.getAddress() == null)
				throw new NullPointerException();
			if (raw.getPort() == 0)
				throw new NullPointerException();
			
			// Create a new task to process this message
			Runnable task = new Runnable() {
				public void run() {
					receiveMessage(raw);
				}
			};
			executeTask(task);
		}
		
		/*
		 * The endpoint's executor executes this method to convert the raw bytes
		 * into a message, look for an associated exchange and forward it to
		 * the stack of layers.
		 */
		private void receiveMessage(RawData raw) {
			DataParser parser = new DataParser(raw.getBytes());
			
			if (parser.isRequest()) {
				// This is a request
				Request request;
				try {
					request = parser.parseRequest();
				} catch (IllegalStateException e) {
					String log = "message format error caused by " + raw.getInetSocketAddress();
					if (!parser.isReply()) {
						// manually build RST from raw information
						EmptyMessage rst = new EmptyMessage(Type.RST);
						rst.setDestination(raw.getAddress());
						rst.setDestinationPort(raw.getPort());
						rst.setMID(parser.getMID());
						for (MessageInterceptor interceptor:interceptors)
							interceptor.sendEmptyMessage(rst);
						connector.send(serializer.serialize(rst));
						log += " and reseted";
					}
					LOGGER.info(log);
					return;
				}
				request.setSource(raw.getAddress());
				request.setSourcePort(raw.getPort());
				
				/* 
				 * Logging here causes significant performance loss.
				 * If necessary, add an interceptor that logs the messages,
				 * e.g., the MessageTracer.
				 */
				
				for (MessageInterceptor interceptor:interceptors)
					interceptor.receiveRequest(request);

				// MessageInterceptor might have canceled
				if (!request.isCanceled()) {
					Exchange exchange = matcher.receiveRequest(request);
					if (exchange != null) {
						exchange.setEndpoint(CoAPEndpoint.this);
						coapstack.receiveRequest(exchange, request);
					}
				}
				
			} else if (parser.isResponse()) {
				// This is a response
				Response response = parser.parseResponse();
				response.setSource(raw.getAddress());
				response.setSourcePort(raw.getPort());
				
				/* 
				 * Logging here causes significant performance loss.
				 * If necessary, add an interceptor that logs the messages,
				 * e.g., the MessageTracer.
				 */
				
				for (MessageInterceptor interceptor:interceptors)
					interceptor.receiveResponse(response);

				// MessageInterceptor might have canceled
				if (!response.isCanceled()) {
					Exchange exchange = matcher.receiveResponse(response);
					if (exchange != null) {
						exchange.setEndpoint(CoAPEndpoint.this);
						response.setRTT(System.currentTimeMillis() - exchange.getTimestamp());
						coapstack.receiveResponse(exchange, response);
					}
				}
				
			} else if (parser.isEmpty()) {
				// This is an empty message
				EmptyMessage message = parser.parseEmptyMessage();
				message.setSource(raw.getAddress());
				message.setSourcePort(raw.getPort());
				
				/* 
				 * Logging here causes significant performance loss.
				 * If necessary, add an interceptor that logs the messages,
				 * e.g., the MessageTracer.
				 */
				
				for (MessageInterceptor interceptor:interceptors)
					interceptor.receiveEmptyMessage(message);

				// MessageInterceptor might have canceled
				if (!message.isCanceled()) {
					// CoAP Ping
					if (message.getType() == Type.CON || message.getType() == Type.NON) {
						EmptyMessage rst = EmptyMessage.newRST(message);
						
						LOGGER.info("Responding to ping by " + raw.getInetSocketAddress());
						
						for (MessageInterceptor interceptor:interceptors)
							interceptor.sendEmptyMessage(rst);
						connector.send(serializer.serialize(rst));
					
					} else {
						Exchange exchange = matcher.receiveEmptyMessage(message);
						if (exchange != null) {
							exchange.setEndpoint(CoAPEndpoint.this);
							coapstack.receiveEmptyMessage(exchange, message);
						}
					}
				}
			} else {
				LOGGER.finest("Silently ignoring non-CoAP message from " + raw.getInetSocketAddress());
			}
		}

	}
	
	/**
	 * Execute the specified task on the endpoint's executor.
	 *
	 * @param task the task
	 */
	private void executeTask(final Runnable task) {
		executor.execute(new Runnable() {
			public void run() {
				try {
					task.run();
				} catch (Throwable t) {
					t.printStackTrace();
				}
			}
		});
	}
}
