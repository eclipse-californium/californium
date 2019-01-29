/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add field for sender identity
 *                                                    (465073)
 *    Achim Kraus (Bosch Software Innovations GmbH) - move payload string conversion
 *                                                    from toString() to
 *                                                    Message.getPayloadTracingString().
 *                                                    (for message tracing)
 *                                                    set scheme on setOptions(URI)
 *    Achim Kraus (Bosch Software Innovations GmbH) - apply source formatter
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix empty uri query in getURI()
 *    Achim Kraus (Bosch Software Innovations GmbH) - add setSendError()
 *                                                    issue #305
 *    Achim Kraus (Bosch Software Innovations GmbH) - copy user context in
 *                                                    setUserContext()
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce source and destination
 *                                                    EndpointContext
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - check endpoint context for 
 *                                                    setURI
 *    Achim Kraus (Bosch Software Innovations GmbH) - check multicast on setURI
 *                                                    set multicast address as
 *                                                    host URI option. 
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix left timeout calculation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.util.ClockUtil;

/**
 * Request represents a CoAP request and has either the {@link Type} CON or NON
 * and one of the {@link CoAP.Code}s GET, POST, PUT or DELETE. A request must be
 * sent over an {@link Endpoint} to its destination. By default, a request uses
 * the default endpoint defined by {@link EndpointManager}. The server responds
 * with a {@link Response}.
 * <p>
 * A client can send a request and wait for for a response using a synchronous
 * (blocking) call like this:
 * </p>
 * 
 * <pre>
 * Request request = new Request(Code.GET);
 * request.setURI(&quot;coap://example.com:5683/sensors/temperature&quot;);
 * request.send();
 * Response response = request.waitForResponse();
 * </pre>
 * <p>
 * A client may also send requests asynchronously (non-blocking) and define a
 * handler to be invoked when a response arrives. This is in particular useful
 * when a client wants to observe the target resource and react to
 * notifications. For instance:
 * </p>
 * 
 * <pre>
 * Request request = new Request(Code.GET);
 * request.setURI(&quot;coap://example.com:5683/sensors/temperature&quot;);
 * request.setObserve();
 * 
 * request.addMessageObserver(new MessageObserverAdapter() {
 * 
 * 	&#64;Override
 * 	public void onResponse(Response response) {
 * 		if (response.getCode() == ResponseCode.CONTENT) {
 * 			System.out.println(&quot;Received &quot; + response.getPayloadString());
 * 		} else {
 * 			// error handling
 * 		}
 * 	}
 * });
 * request.send();
 * </pre>
 * <p>
 * A client can also modify the options of a request. For example:
 * </p>
 * 
 * <pre>
 * Request post = new Request(Code.POST);
 * post.setPayload("Plain text");
 * post.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN).setAccept(MediaTypeRegistry.TEXT_PLAIN)
 * 		.setIfNoneMatch(true);
 * String response = post.send().waitForResponse().getPayloadString();
 * </pre>
 * 
 * @see Response
 */
public class Request extends Message {

	private static final Pattern IP_PATTERN = Pattern
			.compile("(\\[[0-9a-f:]+\\]|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})");

	/** The request code. */
	private final CoAP.Code code;

	/** Marks this request as multicast request */
	private boolean multicast;

	/** The current response for the request. */
	private Response response;

	private String scheme;

	/** The destination address of this message. */
	@Deprecated
	private InetAddress destination;

	/** The destination port of this message. */
	@Deprecated
	private int destinationPort;

	/** Contextual information about this request */
	private Map<String, String> userContext;

	/**
	 * Creates a request of type {@code CON} for a CoAP code.
	 * 
	 * @param code the request code.
	 */
	public Request(Code code) {
		this(code, Type.CON);
	}

	/**
	 * Creates a request for a CoAP code and message type.
	 * 
	 * @param code the request code.
	 * @param type the message type.
	 */
	public Request(Code code, Type type) {
		super(type);
		this.code = code;
	}

	/**
	 * Gets the request code.
	 *
	 * @return the code
	 */
	public Code getCode() {
		return code;
	}

	@Override
	public int getRawCode() {
		return code == null ? 0 : code.value;
	}

	/**
	 * Gets the scheme.
	 *
	 * @return the scheme
	 */
	public String getScheme() {
		return scheme == null ? CoAP.COAP_URI_SCHEME : scheme;
	}

	/**
	 * Sets the scheme.
	 *
	 * @param scheme the new scheme
	 */
	public void setScheme(String scheme) {
		this.scheme = scheme;
	}

	/**
	 * Tests if this request is a multicast request
	 * 
	 * @return true if this request is a multicast request.
	 */
	public boolean isMulticast() {
		return multicast;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * GET and DELETE request are not intended to have payload.
	 */
	@Override
	public boolean isIntendedPayload() {
		return code != Code.GET && code != Code.DELETE;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Request setPayload(String payload) {
		super.setPayload(payload);
		return this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Request setPayload(byte[] payload) {
		super.setPayload(payload);
		return this;
	}

	/**
	 * Sets this request's CoAP URI.
	 * 
	 * @param uri A CoAP URI as specified by
	 *            <a href="https://tools.ietf.org/html/rfc7252#section-6">
	 *            Section 6 of RFC 7252</a>
	 * @return This request for command chaining.
	 * @throws NullPointerException if the URI is {@code null}.
	 * @throws IllegalArgumentException if the given string is not a valid CoAP
	 *             URI, contains a non-resolvable host name, an unsupported
	 *             scheme or a fragment.
	 */
	public Request setURI(final String uri) {

		if (uri == null) {
			throw new NullPointerException("URI must not be null");
		}

		try {
			String coapUri = uri;
			if (!uri.contains("://")) {
				coapUri = "coap://" + uri;
				LOGGER.warn("update your code to supply an RFC 7252 compliant URI including a scheme");
			}
			return setURI(new URI(coapUri));
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("invalid uri: " + uri, e);
		}
	}

	/**
	 * Sets the destination address and port and options from a given URI.
	 * <p>
	 * This method sets the <em>destination</em> to the IP address that the host
	 * part of the URI has been resolved to and then delegates to the
	 * {@link #setOptions(URI)} method in order to populate the request's
	 * options.
	 * 
	 * @param uri The target URI.
	 * @return This request for command chaining.
	 * @throws NullPointerException if the URI is {@code null}.
	 * @throws IllegalArgumentException if the URI contains a non-resolvable
	 *             host name, an unsupported scheme or a fragment.
	 */
	public Request setURI(final URI uri) {

		if (uri == null) {
			throw new NullPointerException("URI must not be null");
		}

		final String host = uri.getHost() == null ? "localhost" : uri.getHost();

		try {
			if (getDestinationContext() == null) {
				InetAddress destAddress = InetAddress.getByName(host);
				setDestinationContext(new AddressEndpointContext(new InetSocketAddress(destAddress, 0), null));
			}

			return setOptions(new URI(uri.getScheme(), uri.getUserInfo(), host, uri.getPort(), uri.getPath(), uri.getQuery(),
					uri.getFragment()));

		} catch (UnknownHostException e) {
			throw new IllegalArgumentException("cannot resolve host name: " + host);
		} catch (URISyntaxException e) {
			// should not happen because we are creating the URI from an
			// existing URI object
			LOGGER.warn("cannot set URI on request", e);
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Sets this request's options from a given URI as defined in
	 * <a href="https://tools.ietf.org/html/rfc7252#section-6.4">RFC 7252,
	 * Section 6.4</a>.
	 * <p>
	 * This method requires the <em>destination</em> to be set already because
	 * it does not try to resolve a host name that is part of the given URI.
	 * Therefore, this method can be used as an alternative to the
	 * {@link #setURI(String)} and {@link #setURI(URI)} methods when DNS is not
	 * available.
	 * 
	 * @param uri The URI to set the options from.
	 * @return This request for command chaining.
	 * @throws NullPointerException if the URI is {@code null}.
	 * @throws IllegalArgumentException if the URI contains an unsupported
	 *             scheme or contains a fragment.
	 * @throws IllegalStateException if the destination is not set.
	 */
	public Request setOptions(final URI uri) {
		InetAddress destination = getDestination();
		if (uri == null) {
			throw new NullPointerException("URI must not be null");
		} else if (!CoAP.isSupportedScheme(uri.getScheme())) {
			throw new IllegalArgumentException("unsupported URI scheme: " + uri.getScheme());
		} else if (uri.getFragment() != null) {
			throw new IllegalArgumentException("URI must not contain a fragment");
		} else if (destination == null) {
			throw new IllegalStateException("destination address must be set");
		}

		if (uri.getHost() != null) {
			String host = uri.getHost().toLowerCase();
			Matcher matcher = IP_PATTERN.matcher(host);
			if (matcher.matches()) {
				try {
					// host is a literal IP address, so we should be able
					// to "wrap" it without invoking the resolver
					InetAddress hostAddress = InetAddress.getByName(host);
					if (!hostAddress.equals(destination)) {
						throw new IllegalArgumentException("URI's literal host IP address '" + hostAddress
								+ "' does not match request's destination address '" + destination + "'");
					}
				} catch (UnknownHostException e) {
					// this should not happen because we do not need to resolve
					// a host name
					LOGGER.warn("could not parse IP address of URI despite successful IP address pattern matching");
				}
			} else {
				// host contains a host name, put it into Uri-Host option to
				// enable virtual hosts (multiple names, same IP address)
				getOptions().setUriHost(host);
			}
		}

		String uriScheme = uri.getScheme().toLowerCase();
		// The Uri-Port is only for special cases where it differs from
		// the UDP port, usually when Proxy-Scheme is used.
		int port = uri.getPort();
		if (port <= 0) {
			port = CoAP.getDefaultPort(uriScheme);
		}

		EndpointContext destinationContext = getDestinationContext();
		if (destinationContext != null) {
			int destPort = destinationContext.getPeerAddress().getPort();
			if (destPort == 0) {
				destinationContext = null;
			} else if (destPort != port) {
				throw new IllegalArgumentException(
						"URI's port '" + port + "' does not match request's destination port '" + destPort + "'");
			}
		}

		if (destinationContext == null) {
			setDestinationContext(new AddressEndpointContext(new InetSocketAddress(destination, port), getOptions().getUriHost(), null));
		}
		this.scheme = uriScheme;
		// do not set the Uri-Port option unless it is used for proxying
		// (setting Uri-Scheme option)

		// set Uri-Path options
		String path = uri.getPath();
		if (path != null && path.length() > 1) {
			getOptions().setUriPath(path);
		}

		// set Uri-Query options
		String query = uri.getQuery();
		if (query != null) {
			getOptions().setUriQuery(query);
		}

		return this;
	}

	/**
	 * Gets a URI derived from this request's options and properties as defined
	 * by <a href="https://tools.ietf.org/html/rfc7252#section-6.5">RFC 7252,
	 * Section 6.5</a>.
	 * <p>
	 * This method falls back to using <em>localhost</em> as the host part in
	 * the returned URI if both the <em>destination</em> as well as the
	 * <em>Uri-Host</em> option are {@code null} (mostly when receiving a
	 * request without a <em>Uri-Host</em> option).
	 * 
	 * @return The URI string.
	 * @throws IllegalStateException if this request contains options and/or
	 *             properties which cannot be parsed into a URI.
	 */
	public String getURI() {

		String host = getOptions().getUriHost();
		if (host == null) {
			if (getDestination() != null) {
				host = getDestination().getHostAddress();
			} else {
				// used during construction or when receiving
				host = "localhost";
			}
		}

		Integer port = getOptions().getUriPort();
		if (port == null) {
			port = getDestinationPort();
		}
		if (port > 0) {
			if (CoAP.isSupportedScheme(getScheme())) {
				if (CoAP.getDefaultPort(getScheme()) == port) {
					port = -1;
				}
			}
		} else {
			port = -1;
		}
		// according RFC7252, section 6.5, item 7, a empty resource name is represented by "/" as path. 
		// therefore always use the leading "/", even if the uri path is empty. 
		String path = "/" + getOptions().getUriPathString();
		String query = getOptions().getURIQueryCount() > 0 ? getOptions().getUriQueryString() : null;
		try {
			URI uri = new URI(getScheme(), null, host, port, path, query, null);
			// ensure, that non-ascii characters are "percent-encoded"
			return uri.toASCIIString();  
		} catch (URISyntaxException e) {
			throw new IllegalStateException("cannot create URI from request", e);
		}
	}

	/**
	 * Gets the destination address.
	 *
	 * @return the destination
	 * @deprecated
	 */
	public InetAddress getDestination() {
		EndpointContext context = getDestinationContext();
		if (context != null) {
			return context.getPeerAddress().getAddress();
		}
		return destination;
	}

	/**
	 * Sets the destination address.
	 *
	 * Provides a fluent API to chain setters.
	 *
	 * @param destination the new destination
	 * @return this Message
	 * @throws IllegalStateException if destination context is already set.
	 * @deprecated
	 * Note: intended to be removed with {@link #setDestinationPort(int)} and 
	 * {@link Request#prepareDestinationContext()}
	 */
	public Message setDestination(InetAddress destination) {
		if (getDestinationContext() != null) {
			throw new IllegalStateException("destination context already set!");
		}
		this.destination = destination;
		multicast = destination != null && destination.isMulticastAddress();
		return this;
	}

	/**
	 * Gets the destination port.
	 *
	 * @return the destination port
	 * @deprecated
	 */
	public int getDestinationPort() {
		EndpointContext context = getDestinationContext();
		if (context != null) {
			return context.getPeerAddress().getPort();
		}
		return destinationPort;
	}

	/**
	 * Sets the destination port.
	 *
	 * Provides a fluent API to chain setters.
	 *
	 * @param destinationPort the new destination port
	 * @return this Message
	 * @throws IllegalStateException if destination context is already set.
	 * @deprecated
	 * Note: intended to be removed with {@link #setDestination(InetAddress)} and 
	 * {@link Request#prepareDestinationContext()}
	 */
	public Message setDestinationPort(int destinationPort) {
		if (getDestinationContext() != null) {
			throw new IllegalStateException("destination context already set!");
		}
		this.destinationPort = destinationPort;
		return this;
	}


	/**
	 * Gets the authenticated (remote) sender's identity.
	 * 
	 * @return the identity or {@code null} if the sender has not been
	 *         authenticated
	 * @see #getSourceContext()
	 * @deprecated
	 */
	public Principal getSenderIdentity() {
		return getSourceContext().getPeerIdentity();
	}

	/**
	 * Prepare destination endpoint context. If not already available, create it
	 * from the {@link #destination} and {@link #destinationPort}.
	 * 
	 * @throws IllegalStateException if no destination endpoint context is
	 *             available and the destination is missing
	 * @deprecated intended to be removed with {@link #setDestination(InetAddress)} and 
	 * {@link #setDestinationPort(int)}
	 */
	public void prepareDestinationContext() {
		EndpointContext context = getDestinationContext();
		if (context == null) {
			if (destination == null) {
				throw new IllegalStateException("missing destination!");
			}
			context = new AddressEndpointContext(
					new InetSocketAddress(destination, destinationPort),
					getOptions().getUriHost(),
					null);
			super.setDestinationContext(context);
		}
		multicast = context.getPeerAddress().getAddress().isMulticastAddress();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Check, if {@link #destination} is different.
	 * 
	 * @throws IllegalStateException if destination differs.
	 */
	@Override
	public Request setDestinationContext(EndpointContext peerContext) {
		if (destination != null) {
			if (!destination.equals(peerContext.getPeerAddress().getAddress())) {
				throw new IllegalStateException("different destination!");
			}
		}
		super.setRequestDestinationContext(peerContext);
		multicast = peerContext != null && peerContext.getPeerAddress().getAddress().isMulticastAddress();
		return this;
	}

	/**
	 * Sends the request over the default endpoint to its destination and
	 * expects a response back.
	 * 
	 * @return this request
	 * @throws NullPointerException if this request has no destination set.
	 */
	public Request send() {
		validateBeforeSending();
		EndpointManager.getEndpointManager().getDefaultEndpoint(getScheme()).sendRequest(this);
		return this;
	}

	/**
	 * Sends this request over the specified endpoint to its destination and
	 * expects a response back.
	 * 
	 * @param endpoint the endpoint
	 * @return this request
	 * @throws NullPointerException if this request has no destination set.
	 */
	public Request send(Endpoint endpoint) {
		validateBeforeSending();
		endpoint.sendRequest(this);
		return this;
	}

	/**
	 * Validate before sending that there is a destination set.
	 */
	private void validateBeforeSending() {
		if (getDestination() == null) {
			throw new NullPointerException("Destination is null");
		}
		if (getDestinationPort() == 0) {
			throw new NullPointerException("Destination port is 0");
		}
	}

	/**
	 * Sets CoAP's observe option. If the target resource of this request
	 * responds with a success code and also sets the observe option, it will
	 * send more responses in the future whenever the resource's state changes.
	 * 
	 * @return this Request
	 * @throws IllegalStateException if this is not a GET request.
	 */
	public final Request setObserve() {
		if (!CoAP.isObservable(code)) {
			throw new IllegalStateException("observe option can only be set on a GET or FETCH request");
		}
		getOptions().setObserve(0);
		return this;
	}

	/**
	 * Checks if this request is used to establish an observe relation.
	 * 
	 * @return {@code true} if this request's <em>observe</em> option is set to
	 *         0.
	 */
	public final boolean isObserve() {
		return isObserveOption(0);
	}

	/**
	 * Sets CoAP's observe option to the value of 1 to proactively cancel.
	 * 
	 * @return this Request
	 * @throws IllegalStateException if this is not a GET request.
	 */
	public final Request setObserveCancel() {
		if (!CoAP.isObservable(code)) {
			throw new IllegalStateException("observe option can only be set on a GET or FETCH request");
		}
		getOptions().setObserve(1);
		return this;
	}

	/**
	 * Checks if this request is used to cancel an observe relation.
	 * 
	 * @return {@code true} if this request's <em>observe</em> option is set to
	 *         1.
	 */
	public final boolean isObserveCancel() {
		return isObserveOption(1);
	}

	/**
	 * Checks if this request is used to manage an observe relation.
	 * 
	 * @param observe value for observe option
	 * @return {@code true} if this request's <em>observe</em> option matches
	 *         the observe parameter, {@code false}, otherwise.
	 */
	private final boolean isObserveOption(int observe) {
		Integer optionObserver = getOptions().getObserve();
		return optionObserver != null && optionObserver.intValue() == observe;
	}

	/**
	 * Gets the response or null if none has arrived yet.
	 *
	 * @return the response
	 */
	public synchronized Response getResponse() {
		return response;
	}

	/**
	 * Sets the response.
	 * <p>
	 * Also notifies waiting threads and invokes this request's registered
	 * {@code MessageHandler}s <em>onResponse</em> method with the response.
	 * </p>
	 * 
	 * @param response the new response
	 */
	public void setResponse(Response response) {
		synchronized (this) {
			this.response = response;
			notifyAll();
		}

		for (MessageObserver handler : getMessageObservers()) {
			handler.onResponse(response);
		}
	}

	/**
	 * Wait for the response. This function blocks until there is a response or
	 * the request has been canceled.
	 * 
	 * @return the response
	 * @throws InterruptedException the interrupted exception
	 */
	public Response waitForResponse() throws InterruptedException {
		return waitForResponse(0);
	}

	/**
	 * Waits for the arrival of the response to this request.
	 * <p>
	 * This function blocks until there is a response, the request has been
	 * canceled or the specified timeout has expired. A timeout of 0 is
	 * interpreted as infinity. If a response is already here, this method
	 * returns it immediately.
	 * <p>
	 * The calling thread returns if either a response arrives, the request gets
	 * rejected by the server, the request gets canceled or, in case of a
	 * confirmable request, timeouts. In that case, if no response has arrived
	 * yet the return value is null.
	 * <p>
	 * This method also sets the response to null so that succeeding calls will
	 * wait for the next response. Repeatedly calling this method is useful if
	 * the client expects multiple responses, e.g., multiple notifications to an
	 * observe request or multiple responses to a multicast request.
	 * 
	 * @param timeout the maximum time to wait in milliseconds.
	 * @return the response (null if timeout occurred)
	 * @throws InterruptedException the interrupted exception
	 */
	public Response waitForResponse(long timeout) throws InterruptedException {
		long expiresNano = ClockUtil.nanoRealtime() + TimeUnit.MILLISECONDS.toNanos(timeout);
		long leftTimeout = timeout;
		synchronized (this) {
			while (this.response == null && !isCanceled() && !isTimedOut() && !isRejected() && getSendError() == null) {
				wait(leftTimeout);
				// timeout expired?
				if (timeout > 0) {
					long leftNanos = expiresNano - ClockUtil.nanoRealtime();
					if (leftNanos <= 0) {
						// break loop
						break;
					}
					// add 1 millisecond to prevent last wait with 0!
					leftTimeout = TimeUnit.NANOSECONDS.toMillis(leftNanos) + 1;
				}
			}
			Response r = this.response;
			this.response = null;
			return r;
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Furthermore, if the request is canceled, it will wake up all threads that
	 * are currently waiting for a response.
	 */
	@Override
	public void setTimedOut(boolean timedOut) {
		super.setTimedOut(timedOut);
		if (timedOut) {
			synchronized (this) {
				notifyAll();
			}
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Furthermore, if the request is canceled, it will wake up all threads that
	 * are currently waiting for a response.
	 */
	@Override
	public void setCanceled(boolean canceled) {
		super.setCanceled(canceled);
		if (canceled) {
			synchronized (this) {
				notifyAll();
			}
		}
	}

	@Override
	public void setRejected(boolean rejected) {
		super.setRejected(rejected);
		if (rejected) {
			synchronized (this) {
				notifyAll();
			}
		}
	}

	@Override
	public void setSendError(Throwable sendError) {
		super.setSendError(sendError);
		if (sendError != null) {
			synchronized (this) {
				notifyAll();
			}
		}
	}

	/**
	 * @return an unmodifiable map containing additional information about this
	 *         request.
	 */
	public Map<String, String> getUserContext() {
		return userContext;
	}

	/**
	 * Set contextual information about this request.
	 * 
	 * @param userContext
	 * @return this request
	 */
	public Request setUserContext(Map<String, String> userContext) {
		if (userContext == null || userContext.isEmpty()) {
			this.userContext = Collections.emptyMap();
		} else {
			this.userContext = Collections.unmodifiableMap(new HashMap<String, String>(userContext));
		}
		return this;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		String payload = getPayloadTracingString();
		return String.format("%s-%-6s MID=%5d, Token=%s, OptionSet=%s, %s", getType(), getCode(), getMID(),
				getTokenString(), getOptions(), payload);
	}

	////////// Some static factory methods for convenience //////////

	/**
	 * Convenience factory method to construct a GET request and equivalent to
	 * <code>new Request(Code.GET);</code>
	 * 
	 * @return a new GET request
	 */
	public static Request newGet() {
		return new Request(Code.GET);
	}

	/**
	 * Convenience factory method to construct a POST request and equivalent to
	 * <code>new Request(Code.POST);</code>
	 * 
	 * @return a new POST request
	 */
	public static Request newPost() {
		return new Request(Code.POST);
	}

	/**
	 * Convenience factory method to construct a PUT request and equivalent to
	 * <code>new Request(Code.PUT);</code>
	 * 
	 * @return a new PUT request
	 */
	public static Request newPut() {
		return new Request(Code.PUT);
	}

	/**
	 * Convenience factory method to construct a DELETE request and equivalent
	 * to <code>new Request(Code.DELETE);</code>
	 * 
	 * @return a new DELETE request
	 */
	public static Request newDelete() {
		return new Request(Code.DELETE);
	}
}
