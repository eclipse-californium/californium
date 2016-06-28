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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add field for sender identity
 *                                                    (465073)
 *    Achim Kraus (Bosch Software Innovations GmbH) - move payload string conversion
 *    												  from toString() to
 *                                                    Message.getPayloadTracingString(). 
 *                                                    (for message tracing)
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;

/**
 * Request represents a CoAP request and has either the {@link Type} CON or NON
 * and one of the {@link CoAP.Code}s GET, POST, PUT or DELETE. A request must be
 * sent over an {@link Endpoint} to its destination. By default, a request
 * uses the default endpoint defined by {@link EndpointManager}. The server
 * responds with a {@link Response}.
 * <p>
 * A client can send a request and wait for for a response using a synchronous
 * (blocking) call like this:
 * </p>
 * <pre>
 * Request request = new Request(Code.GET);
 * request.setURI(&quot;coap://example.com:5683/sensors/temperature&quot;);
 * request.send();
 * Response response = request.waitForResponse();
 * </pre>
 * <p>
 * A client may also send requests asynchronously (non-blocking) and define a
 * handler to be invoked when a response arrives. This is in particular useful
 * when a client wants to observe the target resource and react to notifications.
 * For instance:
 * </p>
 * <pre>
 * Request request = new Request(Code.GET);
 * request.setURI(&quot;coap://example.com:5683/sensors/temperature&quot;);
 * request.setObserve();
 * 
 * request.addMessageObserver(new MessageObserverAdapter() {
 * 
 *   @Override
 *   public void onResponse(Response response) {
 *     if (response.getCode() == ResponseCode.CONTENT) {
 *       System.out.println(&quot;Received &quot; + response.getPayloadString());
 *     } else {
 *       // error handling
 *     }
 *   }
 * });
 * request.send();
 * </pre>
 * <p>
 * A client can also modify the options of a request. For example:
 * </p>
 * <pre>
 * Request post = new Request(Code.POST);
 * post.setPayload("Plain text");
 * post.getOptions()
 *   .setContentFormat(MediaTypeRegistry.TEXT_PLAIN)
 *   .setAccept(MediaTypeRegistry.TEXT_PLAIN)
 *   .setIfNoneMatch(true);
 * String response = post.send().waitForResponse().getPayloadString();
 * </pre>
 * 
 * @see Response
 */
public class Request extends Message {

	private static final Pattern IP_PATTERN = Pattern.compile("(\\[[0-9a-f:]+\\]|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})");

	/** The request code. */
	private final CoAP.Code code;

	/** Marks this request as multicast request */
	private boolean multicast;

	/** The current response for the request. */
	private Response response;

	private String scheme;

	/** The lock object used to wait for a response. */
	private Object lock;

	/** the authenticated (remote) sender's identity */
	private Principal senderIdentity;

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
		return code.value;
	}

	/**
	 * Gets the scheme.
	 *
	 * @return the scheme
	 */
	public String getScheme() {
		return scheme;
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
	 * Defines whether this request is a multicast request or not.
	 * 
	 * @param multicast if this request is a multicast request
	 */
	public void setMulticast(boolean multicast) {
		this.multicast = multicast;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Required in Request to keep class for fluent API.
	 */
	@Override
	public Request setPayload(String payload) {
		super.setPayload(payload);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Required in Request to keep class for fluent API.
	 */
	@Override
	public Request setPayload(byte[] payload) {
		super.setPayload(payload);
		return this;
	}

	/**
	 * Sets this request's CoAP URI.
	 * 
	 * @param uri A CoAP URI as specified by <a href="https://tools.ietf.org/html/rfc7252#section-6">
	 *            Section 6 of RFC 7252</a>
	 * @return This request for command chaining.
	 * @throws IllegalArgumentException if the given string is not a valid CoAP URI, contains a non-resolvable
	 *                                  host name or contains an unsupported scheme.
	 */
	public Request setURI(final String uri) {
		try {
			String coapUri = uri;
			if (!uri.startsWith("coap://") && !uri.startsWith("coaps://") && !uri.startsWith("coap+tcp://")
					&& !uri.startsWith("coaps+tcp://")) {
				coapUri = "coap://" + uri;
				LOGGER.log(Level.WARNING, "update your code to supply an RFC 7252 compliant URI including a scheme");
			}
			return setURI(new URI(coapUri));
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("invalid uri: " + uri, e);
		}
	}

	/**
	 * This is a convenience method to set the request's options for host, port
	 * and path with a URI object.
	 * 
	 * @param uri the URI defining the target resource
	 * @return this request
	 * @throws IllegalArgumentException if the URI contains a non-resolvable host name.
	 */
	public Request setURI(final URI uri) {

		final String host = uri.getHost() == null ? "localhost" : uri.getHost();
		final String uriScheme = uri.getScheme();

		try {

			// first validate URI for correctness

			if (!isSupportedScheme(uriScheme)) {
				throw new IllegalArgumentException("unsupported URI scheme: " + uriScheme);
			}

			InetAddress destAddress = InetAddress.getByName(host);

			// now set properties of this request accordingly

			this.scheme = uriScheme;
			setDestination(destAddress);

			if (!host.equals("localhost")) {
				Matcher matcher = IP_PATTERN.matcher(host.toLowerCase());
				if (!matcher.matches()) {
					// host part of URI is a host name (not an IP address)
					// which we need to put into Uri-Host option
					getOptions().setUriHost(host);
				}
			}

			// The Uri-Port is only for special cases where it differs from the UDP port,
			// usually when Proxy-Scheme is used.
			int port = uri.getPort();
			if (port <= 0) {
				// port has not been specified in URI, use default port for scheme
				if (uriScheme.equals(CoAP.COAP_URI_SCHEME) || uriScheme.equals(CoAP.COAP_TCP_URI_SCHEME)) {
					port = CoAP.DEFAULT_COAP_PORT;
				} else if (uriScheme.equals(CoAP.COAP_SECURE_URI_SCHEME)|| uriScheme.equals(CoAP.COAP_SECURE_TCP_URI_SCHEME)) {
					port = CoAP.DEFAULT_COAP_SECURE_PORT;
				}
			}

			setDestinationPort(port);
			if (port != CoAP.DEFAULT_COAP_PORT) {
				getOptions().setUriPort(port);
			}

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

		} catch (UnknownHostException e) {
			throw new IllegalArgumentException("cannot resolve host name: " + host);
		}
	}

	private boolean isSupportedScheme(final String uriScheme) {
		return CoAP.COAP_URI_SCHEME.equalsIgnoreCase(uriScheme) ||
				CoAP.COAP_TCP_URI_SCHEME.equalsIgnoreCase(uriScheme) ||
				CoAP.COAP_SECURE_URI_SCHEME.equalsIgnoreCase(uriScheme) ||
				CoAP.COAP_SECURE_TCP_URI_SCHEME.equalsIgnoreCase(uriScheme);
	}

	// TODO: test this method.
	/**
	 * Gets the absolute Request-URI as string.
	 * <p>
	 * To support virtual servers, it either uses the Uri-Host option
	 * or "localhost" if the option is not present.
	 * </p>
	 * 
	 * @return the absolute URI string
	 */
	public String getURI() {

		StringBuilder builder = new StringBuilder();
		if (getScheme() != null) {
			builder.append(getScheme()).append("://");
		} else {
			builder.append("coap://");
		}
		String host = getOptions().getUriHost();
		if (host != null) {
			builder.append(host);
		} else {
			builder.append("localhost");
		}
		Integer port = getOptions().getUriPort();
		if (port != null) {
			builder.append(":").append(port);
		}
		String path = getOptions().getUriPathString();
		builder.append("/").append(path);
		String query = getOptions().getUriQueryString();
		if (query.length() > 0) {
			builder.append("?").append(query);
		}
		// TODO: Query as well?
		return builder.toString();
	}

	/**
	 * Gets the authenticated (remote) sender's identity.
	 * 
	 * @return the identity or <code>null</code> if the sender has
	 *             not been authenticated
	 */
	public Principal getSenderIdentity() {
		return this.senderIdentity;
	}

	/**
	 * Sets the authenticated (remote) sender's identity.
	 * 
	 * This method is invoked by <em>Californium</em> when receiving
	 * a request from a client in order to include the client's
	 * authenticated identity. It has no effect on outbound
	 * requests sent to other CoAP servers. In particular,
	 * it has no impact on a DTLS handshake (potentially) taking
	 * place with that server.
	 * 
	 * @param senderIdentity the identity
	 * @return this request
	 */
	public Request setSenderIdentity(Principal senderIdentity) {
		this.senderIdentity = senderIdentity;
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
		if (CoAP.COAP_SECURE_URI_SCHEME.equals(getScheme())) {
			// This is the case when secure coap is supposed to be used
			EndpointManager.getEndpointManager().getDefaultSecureEndpoint().sendRequest(this);
		} else {
			// This is the normal case
			EndpointManager.getEndpointManager().getDefaultEndpoint().sendRequest(this);
		}
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
		if (getDestination() == null)
			throw new NullPointerException("Destination is null");
		if (getDestinationPort() == 0)
			throw new NullPointerException("Destination port is 0");
	}

	/**
	 * Sets CoAP's observe option. If the target resource of this request
	 * responds with a success code and also sets the observe option, it will
	 * send more responses in the future whenever the resource's state changes.
	 * 
	 * @return this Request
	 */
	public Request setObserve() {
		getOptions().setObserve(0);
		return this;
	}

	/**
	 * Sets CoAP's observe option to the value of 1 to proactively cancel.
	 * 
	 * @return this Request
	 */
	public Request setObserveCancel() {
		getOptions().setObserve(1);
		return this;
	}

	/**
	 * Gets the response or null if none has arrived yet.
	 *
	 * @return the response
	 */
	public Response getResponse() {
		return response;
	}

	/**
	 * Sets the response.
	 * <p>
	 * Also notifies waiting threads and invokes this request's registered
	 * @code MessageHandler}s <em>onResponse</em> method with the response.
	 * </p>

	 * @param response
	 *            the new response
	 */
	public void setResponse(Response response) {
		this.response = response;

		// only for synchronous/blocking requests
		if (lock != null) {
			synchronized (lock) {
				lock.notifyAll();
			}
		}
		// else: we know that nobody is waiting on the lock

		for (MessageObserver handler : getMessageObservers()) {
			handler.onResponse(response);
		}
	}

	/**
	 * Wait for the response. This function blocks until there is a response or
	 * the request has been canceled.
	 * 
	 * @return the response
	 * @throws InterruptedException
	 *             the interrupted exception
	 */
	public Response waitForResponse() throws InterruptedException {
		return waitForResponse(0);
	}

	/**
	 * Waits for the arrival of the response to this request.
	 * <p>
	 * This function blocks until there is a response,
	 * the request has been canceled or the specified timeout has expired. A
	 * timeout of 0 is interpreted as infinity. If a response is already here,
	 * this method returns it immediately.
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
		long before = System.currentTimeMillis();
		long expired = timeout>0 ? (before + timeout) : 0;
		// Lazy initialization of a lock
		if (lock == null) {
			synchronized (this) {
				if (lock == null) {
					lock = new Object();
				}
			}
		}
		// wait for response
		synchronized (lock) {
			while (this.response == null && !isCanceled() && !isTimedOut() && !isRejected()) {
				lock.wait(timeout);
				long now = System.currentTimeMillis();
				// timeout expired?
				if (timeout > 0 && expired <= now) {
					// break loop since response is still null
					break;
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
		if (timedOut && lock != null) {
			synchronized (lock) {
				lock.notifyAll();
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
		if (canceled && lock != null) {
			synchronized (lock) {
				lock.notifyAll();
			}
		}
	}

	@Override
	public void setRejected(boolean rejected) {
		super.setRejected(rejected);
		if (rejected  && lock != null) {
			synchronized (lock) {
				lock.notifyAll();
			}
		}
	}

	/**
	 * @return an unmodifiable map containing additional information about this
	 *         request.
	 */
	public Map<String, String> getUserContext() {
		if (userContext == null) {
			return Collections.emptyMap();
		}
		return Collections.unmodifiableMap(userContext);
	}

	/**
	 * Set contextual information about this request.
	 * 
	 * @param userContext
	 * @return this request
	 */
	public Request setUserContext(Map<String, String> userContext) {
		this.userContext = userContext;
		return this;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		String payload = getPayloadTracingString();
		return String.format("%s-%-6s MID=%5d, Token=%s, OptionSet=%s, %s", getType(), getCode(), getMID(), getTokenString(), getOptions(), payload);
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
