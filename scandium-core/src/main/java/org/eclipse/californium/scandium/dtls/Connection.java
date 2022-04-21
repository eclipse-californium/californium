/*******************************************************************************
 * Copyright (c) 2015, 2017 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for terminating a handshake
 *    Bosch Software Innovations GmbH - add constructor based on current connection state
 *    Achim Kraus (Bosch Software Innovations GmbH) - make pending flight and handshaker
 *                                                    access thread safe.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add handshakeFailed.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use volatile for establishedSession.
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - add automatic resumption
 *    Achim Kraus (Bosch Software Innovations GmbH) - add session id to resume
 *                                                    connections created based
 *                                                    on the client session cache.
 *                                                    remove unused constructor.
 *    Achim Kraus (Bosch Software Innovations GmbH) - issue 744: use handshaker as 
 *                                                    parameter for session listener.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add handshakeFlightRetransmitted
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign connection session listener to
 *                                                    ensure, that the session listener methods
 *                                                    are called via the handshaker.
 *    Achim Kraus (Bosch Software Innovations GmbH) - move DTLSFlight to Handshaker
 *    Achim Kraus (Bosch Software Innovations GmbH) - move serial executor from dtlsconnector
 *    Achim Kraus (Bosch Software Innovations GmbH) - add connection id as primary 
 *                                                    lookup key. redesign to make 
 *                                                    the connection modifiable
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.ConcurrentModificationException;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext.Attributes;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DataStreamReader;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.SerialExecutor;
import org.eclipse.californium.elements.util.SerialExecutor.ExecutionListener;
import org.eclipse.californium.elements.util.SerializationUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.ConnectionListener;
import org.eclipse.californium.scandium.DatagramFilter;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Information about the DTLS connection to a peer.
 * 
 * Contains status information regarding
 * <ul>
 * <li>a potentially ongoing handshake with the peer</li>
 * <li>an already established session with the peer</li>
 * </ul>
 */
public final class Connection {

	private static final Logger LOGGER = LoggerFactory.getLogger(Connection.class);
	private static final Logger LOGGER_OWNER = LoggerFactory.getLogger(LOGGER.getName() + ".owner");

	private final AtomicReference<Handshaker> ongoingHandshake = new AtomicReference<Handshaker>();
	private final SessionListener sessionListener = new ConnectionSessionListener();

	private volatile ConnectionListener connectionListener;

	/**
	 * Identifier of the Client Hello used to start the handshake.
	 * 
	 * Maybe {@code null}, for client side connections.
	 * 
	 * Note: used outside of the serial-execution!
	 * 
	 * @since 3.0
	 */
	private volatile ClientHelloIdentifier startingHelloClient;

	/**
	 * Established {@link DTLSContext}.
	 */
	private volatile DTLSContext establishedDtlsContext;

	/**
	 * Mark connection to require an abbreviated handshake.
	 * 
	 * Used to know when an abbreviated handshake should be initiated.
	 */
	private volatile boolean resumptionRequired;

	/**
	 * Mark connection as double though the principal has already a newer
	 * connection.
	 * 
	 * @since 3.5
	 */
	private volatile boolean doublePrincipal;

	/**
	 * Expired real time nanoseconds of the last message send or received.
	 */
	private long lastMessageNanos;
	private long lastPeerAddressNanos;
	private SerialExecutor serialExecutor;
	private InetSocketAddress peerAddress;
	private InetSocketAddress router;
	private ConnectionId cid;
	/**
	 * Data of this connection specific for the used {@link DatagramFilter}.
	 * 
	 * @since 3.6
	 */
	private Object filterData;

	/**
	 * Root cause of alert.
	 * 
	 * For some case, the root cause may be hidden and replaced by a general
	 * cause when sending an alert message. This keeps the root cause for
	 * internal analysis.
	 * 
	 * @since 2.5
	 */
	private AlertMessage rootCause;

	/**
	 * Creates a new connection to a given peer.
	 * 
	 * @param peerAddress the IP address and port of the peer the connection
	 *            exists with
	 * @throws NullPointerException if the peer address is {@code null}
	 */
	public Connection(InetSocketAddress peerAddress) {
		if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		} else {
			long now = ClockUtil.nanoRealtime();
			this.peerAddress = peerAddress;
			this.lastPeerAddressNanos = now;
			this.lastMessageNanos = now;
		}
	}

	/**
	 * Update connection state.
	 * 
	 * Calls {@link ConnectionListener#updateExecution(Connection)}.
	 * 
	 * @since 2.4
	 */
	public void updateConnectionState() {
		ConnectionListener listener = this.connectionListener;
		if (listener != null) {
			listener.updateExecution(this);
		}
	}

	/**
	 * Set connector's context.
	 * 
	 * @param executor executor to be used for {@link SerialExecutor}.
	 * @param listener connection listener.
	 * @return this connection
	 * @throws IllegalStateException if the connection is already executing
	 * @since 3.0 (combines previous setExecutor and setExecutionListener)
	 */
	public Connection setConnectorContext(Executor executor, ConnectionListener listener) {
		if (isExecuting()) {
			throw new IllegalStateException("Executor already available!");
		}
		this.serialExecutor = new SerialExecutor(executor);
		this.connectionListener = listener;
		if (listener == null) {
			serialExecutor.setExecutionListener(null);
		} else {
			serialExecutor.setExecutionListener(new ExecutionListener() {

				@Override
				public void beforeExecution() {
					connectionListener.beforeExecution(Connection.this);
				}

				@Override
				public void afterExecution() {
					connectionListener.afterExecution(Connection.this);
				}
			});
		}
		return this;
	}

	/**
	 * Gets the serial executor assigned to this connection.
	 * 
	 * @return serial executor. May be {@code null}, if the connection is
	 *         restored on startup.
	 */
	public SerialExecutor getExecutor() {
		return serialExecutor;
	}

	/**
	 * Checks, if the connection has a executing serial executor.
	 * 
	 * @return {@code true}, if the connection has an executing serial executor.
	 *         {@code false}, if no serial executor is available, or the
	 *         executor is shutdown.
	 */
	public boolean isExecuting() {
		return serialExecutor != null && !serialExecutor.isShutdown();
	}

	/**
	 * Get session listener of connection.
	 * 
	 * @return session listener.
	 */
	public final SessionListener getSessionListener() {
		return sessionListener;
	}

	/**
	 * Checks whether this connection is either in use on this node or can be
	 * resumed by peers interacting with this node.
	 * <p>
	 * A connection that is not active is currently being negotiated by means of
	 * the <em>ongoingHandshake</em>.
	 * 
	 * @return {@code true} if this connection either already has an established
	 *         session or contains a session that it can be resumed from.
	 */
	public boolean isActive() {
		return establishedDtlsContext != null;
	}

	/**
	 * Check, if this connection expects connection ID for incoming records.
	 * 
	 * @return {@code true}, if connection ID is expected, {@code false},
	 *         otherwise
	 */
	public boolean expectCid() {
		DTLSContext context = getDtlsContext();
		return context != null && ConnectionId.useConnectionId(context.getReadConnectionId());
	}

	/**
	 * Gets the connection id.
	 * 
	 * @return the cid
	 */
	public ConnectionId getConnectionId() {
		return cid;
	}

	/**
	 * Sets the connection id.
	 * 
	 * @param cid the connection id
	 */
	public void setConnectionId(ConnectionId cid) {
		this.cid = cid;
		updateConnectionState();
	}

	/**
	 * Set filter data.
	 * 
	 * Intended to be used by {@link DatagramFilter} implementations. The filter
	 * data is not persisted and considered to be short living.
	 * 
	 * @param filterData filter specific data
	 * @since 3.6
	 */
	public void setFilterData(Object filterData) {
		this.filterData = filterData;
	}

	/**
	 * Get filter data.
	 * 
	 * Intended to be used by {@link DatagramFilter} implementations. The filter
	 * data is not persisted and considered to be short living.
	 * 
	 * @return filter data. May be {@code null}.
	 * @since 3.6
	 */
	public Object getFilterData() {
		return filterData;
	}

	/**
	 * Get real time nanoseconds of last
	 * {@link #updatePeerAddress(InetSocketAddress)}.
	 * 
	 * @return real time nanoseconds
	 * @see ClockUtil#nanoRealtime()
	 */
	public long getLastPeerAddressNanos() {
		return lastPeerAddressNanos;
	}

	/**
	 * Gets the address of this connection's peer.
	 * 
	 * @return the address
	 */
	public InetSocketAddress getPeerAddress() {
		return peerAddress;
	}

	/**
	 * Update the address of this connection's peer.
	 * 
	 * If the new address is {@code null}, an ongoing handshake is failed. A
	 * non-null address could only be applied, if the dtls context is
	 * established.
	 * 
	 * Note: to keep track of the associated address in the connection store,
	 * this method must not be called directly. It must be called by calling
	 * {@link ResumptionSupportingConnectionStore#update(Connection, InetSocketAddress)}
	 * or
	 * {@link ResumptionSupportingConnectionStore#remove(Connection, boolean)}.
	 * 
	 * @param peerAddress the address of the peer
	 * @throws IllegalArgumentException if the address should be updated with a
	 *             non-null value without an established dtls context.
	 */
	public void updatePeerAddress(InetSocketAddress peerAddress) {
		if (!equalsPeerAddress(peerAddress)) {
			if (establishedDtlsContext == null && peerAddress != null) {
				throw new IllegalArgumentException("Address change without established dtls context is not supported!");
			}
			this.lastPeerAddressNanos = ClockUtil.nanoRealtime();
			InetSocketAddress previous = this.peerAddress;
			this.peerAddress = peerAddress;
			if (peerAddress == null) {
				final Handshaker pendingHandshaker = getOngoingHandshake();
				if (pendingHandshaker != null) {
					if (establishedDtlsContext == null
							|| pendingHandshaker.getDtlsContext() != establishedDtlsContext) {
						// this will only call the listener, if no other cause was set before!
						pendingHandshaker.handshakeFailed(new IOException(
								StringUtil.toDisplayString(previous) + " address reused during handshake!"));
					}
				}
			} else {
				// only update mdc, if address is changed to new one.
				updateConnectionState();
			}
		}
	}

	/**
	 * Check, if the provided address is the peers address.
	 * 
	 * @param peerAddress provided peer address
	 * @return {@code true}, if the addresses are equal
	 */
	public boolean equalsPeerAddress(InetSocketAddress peerAddress) {
		if (this.peerAddress == peerAddress) {
			return true;
		} else if (this.peerAddress == null) {
			return false;
		}
		return this.peerAddress.equals(peerAddress);
	}

	/**
	 * Gets the address of this connection's router.
	 * 
	 * @return the address of the router
	 * @since 2.5
	 */
	public InetSocketAddress getRouter() {
		return router;
	}

	/**
	 * Sets the address of this connection's router.
	 * 
	 * @param router the address of the router
	 * @since 2.5
	 */
	public void setRouter(InetSocketAddress router) {
		if (this.router != router && (this.router == null || !this.router.equals(router))) {
			this.router = router;
			updateConnectionState();
		}
	}

	/**
	 * Get endpoint context for writing messages.
	 * 
	 * @param attributes initial attributes
	 * @return endpoint context for writing messages.
	 * @throws IllegalStateException if dtls context is not established
	 * @since 3.0
	 */
	public DtlsEndpointContext getWriteContext(Attributes attributes) {
		if (establishedDtlsContext == null) {
			throw new IllegalStateException("DTLS context must be established!");
		}
		establishedDtlsContext.addWriteEndpointContext(attributes);
		if (router != null) {
			attributes.add(DtlsEndpointContext.KEY_VIA_ROUTER, "dtls-cid-router");
		}
		DTLSSession session = establishedDtlsContext.getSession();
		return new DtlsEndpointContext(peerAddress, session.getHostName(), session.getPeerIdentity(), attributes);
	}

	/**
	 * Get endpoint context for reading messages.
	 * 
	 * @param attributes initial attributes
	 * @param recordsPeer peer address of record. Only used, if connection has
	 *            no {@link #peerAddress}.
	 * 
	 * @return endpoint context for reading messages.
	 * @since 3.0
	 */
	public DtlsEndpointContext getReadContext(Attributes attributes, InetSocketAddress recordsPeer) {
		if (establishedDtlsContext == null) {
			throw new IllegalStateException("DTLS context must be established!");
		}
		establishedDtlsContext.addReadEndpointContext(attributes);
		if (router != null) {
			attributes.add(DtlsEndpointContext.KEY_VIA_ROUTER, "dtls-cid-router");
		}
		if (peerAddress != null) {
			recordsPeer = peerAddress;
		}
		DTLSSession session = establishedDtlsContext.getSession();
		return new DtlsEndpointContext(recordsPeer, session.getHostName(), session.getPeerIdentity(), attributes);
	}

	/**
	 * Gets the session containing the connection's <em>current</em> state.
	 * 
	 * This is the session of the {@link #establishedDtlsContext}, if not
	 * {@code null}, or the session negotiated in the {@link #ongoingHandshake}.
	 * 
	 * @return the <em>current</em> session, or {@code null}, if no session
	 *         exists
	 */
	public DTLSSession getSession() {
		DTLSContext dtlsContext = getDtlsContext();
		if (dtlsContext != null) {
			return dtlsContext.getSession();
		}
		return null;
	}

	/**
	 * Gets the {@link Principal} of the established session.
	 * 
	 * @return the {@link Principal} of the established session, or
	 *         {@code null}, if not available.
	 * @since 3.5
	 */
	public Principal getEstablishedPeerIdentity() {
		DTLSContext context = getEstablishedDtlsContext();
		return context == null ? null : context.getSession().getPeerIdentity();
	}

	/**
	 * Gets the DTLS session id of an already established DTLS context that
	 * exists with this connection's peer.
	 * 
	 * @return the session id, or {@code null}, if no DTLS context has been
	 *         established (yet)
	 * @since 3.0
	 */
	public SessionId getEstablishedSessionIdentifier() {
		DTLSContext context = getEstablishedDtlsContext();
		return context == null ? null : context.getSession().getSessionIdentifier();
	}

	/**
	 * Gets the DTLS session of an already established DTLS context that exists
	 * with this connection's peer.
	 * 
	 * @return the session, or {@code null}, if no DTLS context has been
	 *         established (yet)
	 */
	public DTLSSession getEstablishedSession() {
		DTLSContext context = getEstablishedDtlsContext();
		return context == null ? null : context.getSession();
	}

	/**
	 * Checks, whether a DTLS context has already been established with the
	 * peer.
	 * 
	 * @return {@code true}, if a DTLS context has been established,
	 *         {@code false}, otherwise.
	 * @since 3.0 (replaces hasEstablishedSession)
	 */
	public boolean hasEstablishedDtlsContext() {
		return establishedDtlsContext != null;
	}

	/**
	 * Gets the already established DTLS context that exists with this
	 * connection's peer.
	 * 
	 * @return the DTLS context, or {@code null}, if no DTLS context has been
	 *         established (yet)
	 */
	public DTLSContext getEstablishedDtlsContext() {
		return establishedDtlsContext;
	}

	/**
	 * Gets the handshaker managing the currently ongoing handshake with the
	 * peer.
	 * 
	 * @return the handshaker, or {@code null}, if no handshake is going on
	 */
	public Handshaker getOngoingHandshake() {
		return ongoingHandshake.get();
	}

	/**
	 * Checks whether there is a handshake going on with the peer.
	 * 
	 * @return {@code true}, if a handshake is going on, {@code false},
	 *         otherwise.
	 */
	public boolean hasOngoingHandshake() {
		return ongoingHandshake.get() != null;
	}

	/**
	 * Check, if this connection belongs to double principal.
	 * 
	 * @return {@code true}, if the principal has already a newer connection,
	 *         {@code false}, if not.
	 * @since 3.5
	 */
	public boolean isDouble() {
		return doublePrincipal;
	}

	/**
	 * Mark connection as double, if the principal has already a newer
	 * connection.
	 * 
	 * @since 3.5
	 */
	public void setDouble() {
		doublePrincipal = true;
	}

	/**
	 * Get system nanos of starting client hello.
	 * 
	 * @return system nanos, or {@code null}, if prevention is expired or not
	 *         used.
	 * @since 3.0
	 */
	public Long getStartNanos() {
		ClientHelloIdentifier start = this.startingHelloClient;
		if (start != null) {
			return start.nanos;
		} else {
			return null;
		}
	}

	/**
	 * Checks whether this connection is started for the provided CLIENT_HELLO.
	 * 
	 * Use the random and message sequence number contained in the CLIENT_HELLO.
	 * 
	 * Note: called outside of serial-execution and so requires external
	 * synchronization!
	 * 
	 * @param clientHello the message to check.
	 * @return {@code true} if the given client hello has initially started this
	 *         connection.
	 * @see #startByClientHello(ClientHello)
	 * @throws NullPointerException if client hello is {@code null}.
	 */
	public boolean isStartedByClientHello(ClientHello clientHello) {
		if (clientHello == null) {
			throw new NullPointerException("client hello must not be null!");
		}
		ClientHelloIdentifier start = this.startingHelloClient;
		if (start != null) {
			return start.isStartedByClientHello(clientHello);
		}
		return false;
	}

	/**
	 * Set starting CLIENT_HELLO.
	 * 
	 * Use the random and handshake message sequence number contained in the
	 * CLIENT_HELLO. Removed, if when the handshake fails or with configurable
	 * timeout after handshake completion.
	 * 
	 * Note: called outside of serial-execution and so requires external
	 * synchronization!
	 * 
	 * @param clientHello message which starts the connection.
	 * @see #isStartedByClientHello(ClientHello)
	 */
	public void startByClientHello(ClientHello clientHello) {
		if (clientHello == null) {
			startingHelloClient = null;
		} else {
			startingHelloClient = new ClientHelloIdentifier(clientHello);
		}
	}

	/**
	 * Gets the DTLS context containing the connection's <em>current</em> state
	 * for the provided epoch.
	 * 
	 * This is the {@link #establishedDtlsContext}, if not {@code null} and the
	 * read epoch is matching. Or the DTLS context negotiated in the
	 * {@link #ongoingHandshake}, if not {@code null} and the read epoch is
	 * matching. If both are {@code null}, or the read epoch doesn't match,
	 * {@code null} is returned.
	 * 
	 * @param readEpoch the read epoch to match.
	 * @return the <em>current</em> DTLS context, or {@code null}, if neither an
	 *         established DTLS context nor an ongoing handshake exists with an
	 *         matching read epoch
	 * @since 3.0 (replaces getSession(int))
	 */
	public DTLSContext getDtlsContext(int readEpoch) {
		DTLSContext context = establishedDtlsContext;
		if (context != null && context.getReadEpoch() == readEpoch) {
			return context;
		}
		Handshaker handshaker = ongoingHandshake.get();
		if (handshaker != null) {
			context = handshaker.getDtlsContext();
			if (context != null && context.getReadEpoch() == readEpoch) {
				return context;
			}
		}
		return null;
	}

	/**
	 * Gets the DTLS context containing the connection's <em>current</em> state.
	 * 
	 * This is the {@link #establishedDtlsContext}, if not {@code null}, or the
	 * DTLS context negotiated in the {@link #ongoingHandshake}.
	 * 
	 * @return the <em>current</em> DTLS context, or {@code null}, if neither an
	 *         established DTLS context nor an ongoing handshake exists
	 * @since 3.0 (replaces getSession())
	 */
	public DTLSContext getDtlsContext() {
		DTLSContext context = establishedDtlsContext;
		if (context == null) {
			Handshaker handshaker = ongoingHandshake.get();
			if (handshaker != null) {
				context = handshaker.getDtlsContext();
			}
		}
		return context;
	}

	/**
	 * Reset DTLS context.
	 * 
	 * Prepare connection for new handshake. Reset established DTLS context or
	 * resume session and remove resumption mark.
	 * 
	 * @throws IllegalStateException if neither a established DTLS context nor a
	 *             resume session is available
	 * @since 3.0 (replaces resetSession())
	 */
	public void resetContext() {
		if (establishedDtlsContext == null) {
			throw new IllegalStateException("No established context to resume available!");
		}
		SecretUtil.destroy(establishedDtlsContext);
		establishedDtlsContext = null;
		resumptionRequired = false;
		startByClientHello(null);
		updateConnectionState();
	}

	/**
	 * Check, if connection was closed.
	 * 
	 * @return {@code true}, if connection was closed, {@code false}, otherwise.
	 * @since 2.3
	 */
	public boolean isClosed() {
		DTLSContext context = establishedDtlsContext;
		return context != null && context.isMarkedAsClosed();
	}

	/**
	 * Close connection with record.
	 * 
	 * Mark session as closed. Received records with sequence numbers before
	 * will still be processed, others are dropped. No message will be send
	 * after this.
	 * 
	 * @param record received close notify record.
	 * @since 2.3
	 */
	public void close(Record record) {
		DTLSContext context = establishedDtlsContext;
		if (context != null) {
			context.markCloseNotify(record.getEpoch(), record.getSequenceNumber());
		}
	}

	/**
	 * Mark record as read in established DTLS context.
	 * 
	 * @param record record to mark as read.
	 * @return {@code true}, if the record is newer than the current newest.
	 *         {@code false}, if not.
	 * @since 3.0
	 */
	public boolean markRecordAsRead(Record record) {
		boolean newest = false;
		DTLSContext context = establishedDtlsContext;
		if (context != null) {
			newest = context.markRecordAsRead(record.getEpoch(), record.getSequenceNumber());
		}
		return newest;
	}

	/**
	 * Gets the root cause alert.
	 * 
	 * For some case, the root cause may be hidden and replaced by a general
	 * cause when sending an alert message. This keeps the root cause for
	 * internal analysis.
	 * 
	 * @return root cause alert.
	 * @since 2.5
	 */
	public AlertMessage getRootCauseAlert() {
		return rootCause;
	}

	/**
	 * Sets root cause alert.
	 * 
	 * For some case, the root cause may be hidden and replaced by a general
	 * cause when sending an alert message. This keeps the root cause for
	 * internal analysis.
	 * 
	 * @param rootCause root cause alert
	 * @return {@code true}, if the root cause is set, {@code false}, if the
	 *         root cause is already set. (Return value added since 3.0)
	 * @since 2.5
	 */
	public boolean setRootCause(AlertMessage rootCause) {
		if (this.rootCause == null) {
			this.rootCause = rootCause;
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Check, if resumption is required.
	 * 
	 * @return {@code true}, if an abbreviated handshake should be done next
	 *         time a data will be sent on this connection.
	 */
	public boolean isResumptionRequired() {
		return resumptionRequired;
	}

	/**
	 * Check, if the automatic session resumption should be triggered or is
	 * already required.
	 * 
	 * @param autoResumptionTimeoutMillis auto resumption timeout in
	 *            milliseconds. {@code null}, if auto resumption is not used.
	 * @return {@code true}, if the provided autoResumptionTimeoutMillis has
	 *         expired without exchanging messages.
	 */
	public boolean isAutoResumptionRequired(Long autoResumptionTimeoutMillis) {
		if (!resumptionRequired && autoResumptionTimeoutMillis != null && establishedDtlsContext != null) {
			long now = ClockUtil.nanoRealtime();
			long expires = lastMessageNanos + TimeUnit.MILLISECONDS.toNanos(autoResumptionTimeoutMillis);
			if ((now - expires) > 0) {
				setResumptionRequired(true);
			}
		}
		return resumptionRequired;
	}

	/**
	 * Refresh auto resumption timeout.
	 * 
	 * Uses {@link ClockUtil#nanoRealtime()}.
	 * 
	 * @see #lastMessageNanos
	 */
	public void refreshAutoResumptionTime() {
		lastMessageNanos = ClockUtil.nanoRealtime();
	}

	/**
	 * Get realtime nanoseconds of last message.
	 * 
	 * @return realtime nanoseconds of last message
	 * @since 3.0
	 */
	public long getLastMessageNanos() {
		return lastMessageNanos;
	}

	/**
	 * Use to force an abbreviated handshake next time a data will be sent on
	 * this connection.
	 * 
	 * @param resumptionRequired true to force abbreviated handshake.
	 */
	public void setResumptionRequired(boolean resumptionRequired) {
		this.resumptionRequired = resumptionRequired;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((cid == null) ? 0 : cid.hashCode());
		result = prime * result + ((establishedDtlsContext == null) ? 0 : establishedDtlsContext.hashCode());
		result = prime * result + (int) (lastMessageNanos ^ (lastMessageNanos >>> 32));
		result = prime * result + ((peerAddress == null) ? 0 : peerAddress.hashCode());
		result = prime * result + (resumptionRequired ? 1231 : 1237);
		result = prime * result + ((router == null) ? 0 : router.hashCode());
		result = prime * result + ((rootCause == null) ? 0 : rootCause.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		Connection other = (Connection) obj;
		if (!Bytes.equals(cid, other.cid)) {
			return false;
		}
		if (resumptionRequired != other.resumptionRequired) {
			return false;
		}
		if (lastMessageNanos != other.lastMessageNanos) {
			return false;
		}
		if (!Objects.equals(establishedDtlsContext, other.establishedDtlsContext)) {
			return false;
		}
		if (!Objects.equals(peerAddress, other.peerAddress)) {
			return false;
		}
		if (!Objects.equals(router, other.router)) {
			return false;
		}
		if (!Objects.equals(rootCause, other.rootCause)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder("dtls-con: ");
		if (cid != null) {
			builder.append(cid);
		}
		if (peerAddress != null) {
			builder.append(", ").append(StringUtil.toDisplayString(peerAddress));
			Handshaker handshaker = getOngoingHandshake();
			if (handshaker != null) {
				builder.append(", ongoing handshake ");
				SessionId id = handshaker.getDtlsContext().getSession().getSessionIdentifier();
				if (id != null && !id.isEmpty()) {
					// during handshake this may by not already set
					builder.append(StringUtil.byteArray2HexString(id.getBytes(), StringUtil.NO_SEPARATOR, 6));
				}
			}
			if (isResumptionRequired()) {
				builder.append(", resumption required");
			} else if (hasEstablishedDtlsContext()) {
				builder.append(", session established ");
				SessionId id = getEstablishedSession().getSessionIdentifier();
				if (id != null && !id.isEmpty()) {
					builder.append(StringUtil.byteArray2HexString(id.getBytes(), StringUtil.NO_SEPARATOR, 6));
				}
			}
		}
		if (isExecuting()) {
			builder.append(", is alive");
		}
		return builder.toString();
	}

	/**
	 * Identifier of starting client hello.
	 * 
	 * Keeps random and handshake message sequence number to prevent from
	 * accidentally starting a handshake again.
	 * 
	 * @since 3.0
	 */
	private static class ClientHelloIdentifier {

		private final Random clientHelloRandom;
		private final long nanos;
		private final int clientHelloMessageSeq;

		private ClientHelloIdentifier(ClientHello clientHello) {
			clientHelloMessageSeq = clientHello.getMessageSeq();
			clientHelloRandom = clientHello.getRandom();
			nanos = ClockUtil.nanoRealtime();
		}

		private ClientHelloIdentifier(DatagramReader reader, long nanoShift) {
			clientHelloMessageSeq = reader.read(Short.SIZE);
			byte[] data = reader.readVarBytes(Byte.SIZE);
			if (data != null) {
				clientHelloRandom = new Random(data);
			} else {
				clientHelloRandom = null;
			}
			nanos = reader.readLong(Long.SIZE) + nanoShift;
		}

		private boolean isStartedByClientHello(ClientHello clientHello) {
			if (clientHelloRandom.equals(clientHello.getRandom())) {
				if (clientHelloMessageSeq >= clientHello.getMessageSeq()) {
					return true;
				}
			}
			return false;
		}

		private void write(DatagramWriter writer) {
			writer.write(clientHelloMessageSeq, Short.SIZE);
			writer.writeVarBytes(clientHelloRandom, Byte.SIZE);
			writer.writeLong(nanos, Long.SIZE);
		}
	}

	private class ConnectionSessionListener implements SessionListener {

		@Override
		public void handshakeStarted(Handshaker handshaker) throws HandshakeException {
			ongoingHandshake.set(handshaker);
			LOGGER.debug("Handshake with [{}] has been started", StringUtil.toLog(peerAddress));
		}

		@Override
		public void contextEstablished(Handshaker handshaker, DTLSContext context) throws HandshakeException {
			establishedDtlsContext = context;
			LOGGER.debug("Session context with [{}] has been established", StringUtil.toLog(peerAddress));
		}

		@Override
		public void handshakeCompleted(Handshaker handshaker) {
			SerialExecutor executor = serialExecutor;
			if (executor != null && !executor.isShutdown() && LOGGER_OWNER.isErrorEnabled()) {
				try {
					executor.assertOwner();
				} catch (ConcurrentModificationException ex) {
					LOGGER_OWNER.error("on handshake completed: connection {}", ex.getMessage(), ex);
					if (LOGGER_OWNER.isDebugEnabled()) {
						throw ex;
					}
				}
			}
			if (ongoingHandshake.compareAndSet(handshaker, null)) {
				LOGGER.debug("Handshake with [{}] has been completed", StringUtil.toLog(peerAddress));
			}
		}

		@Override
		public void handshakeFailed(Handshaker handshaker, Throwable error) {
			SerialExecutor executor = serialExecutor;
			if (executor != null && !executor.isShutdown() && LOGGER_OWNER.isErrorEnabled()) {
				try {
					executor.assertOwner();
				} catch (ConcurrentModificationException ex) {
					LOGGER_OWNER.error("on handshake failed: connection {}", ex.getMessage(), ex);
					if (LOGGER_OWNER.isDebugEnabled()) {
						throw ex;
					}
				}
			}
			if (ongoingHandshake.compareAndSet(handshaker, null)) {
				startingHelloClient = null;
				LOGGER.debug("Handshake with [{}] has failed", StringUtil.toLog(peerAddress));
			}
		}

		@Override
		public void handshakeFlightRetransmitted(Handshaker handshaker, int flight) {
		}
	}

	/**
	 * Version number for serialization.
	 */
	private static final int VERSION = 1;

	/**
	 * Write connection state.
	 * 
	 * Note: the stream will contain not encrypted critical credentials. It is
	 * required to protect this data before exporting it.
	 * 
	 * @param writer writer for connection state
	 * @return {@code true}, if connection is written, {@code false}, if not.
	 * @since 3.0
	 */
	public boolean writeTo(DatagramWriter writer) {
		if (establishedDtlsContext == null || establishedDtlsContext.isMarkedAsClosed() || rootCause != null) {
			return false;
		}
		int position = SerializationUtil.writeStartItem(writer, VERSION, Short.SIZE);
		writer.writeByte(resumptionRequired ? (byte) 1 : (byte) 0);
		writer.writeLong(lastMessageNanos, Long.SIZE);
		writer.writeVarBytes(cid, Byte.SIZE);
		SerializationUtil.write(writer, peerAddress);
		ClientHelloIdentifier start = startingHelloClient;
		if (start == null) {
			writer.writeByte((byte) 0);
		} else {
			writer.writeByte((byte) 1);
			start.write(writer);
		}
		establishedDtlsContext.writeTo(writer);
		writer.writeByte(cid != null && cid.equals(establishedDtlsContext.getReadConnectionId()) ? (byte) 1 : (byte) 0);
		writer.writeByte(doublePrincipal ? (byte) 1 : (byte) 0);
		SerializationUtil.writeFinishedItem(writer, position, Short.SIZE);
		return true;
	}

	/**
	 * Read connection state.
	 * 
	 * @param reader reader with connection state.
	 * @param nanoShift adjusting shift for system time in nanoseconds.
	 * @return read connection.
	 * @throws IllegalArgumentException if version differs or data is erroneous.
	 * @since 3.0
	 */
	public static Connection fromReader(DataStreamReader reader, long nanoShift) {
		int length = SerializationUtil.readStartItem(reader, VERSION, Short.SIZE);
		if (0 < length) {
			DatagramReader rangeReader = reader.createRangeReader(length);
			return new Connection(rangeReader, nanoShift);
		} else {
			return null;
		}
	}

	/**
	 * Create instance from reader.
	 * 
	 * @param reader reader with connection state.
	 * @param nanoShift adjusting shift for system time in nanoseconds.
	 * @throws IllegalArgumentException if the data is erroneous
	 * @since 3.0
	 */
	private Connection(DatagramReader reader, long nanoShift) {
		resumptionRequired = reader.readNextByte() == 1;
		lastMessageNanos = reader.readLong(Long.SIZE) + nanoShift;
		byte[] data = reader.readVarBytes(Byte.SIZE);
		if (data == null) {
			throw new IllegalArgumentException("CID must not be null!");
		}
		cid = new ConnectionId(data);
		peerAddress = SerializationUtil.readAddress(reader);
		if (reader.readNextByte() == 1) {
			startingHelloClient = new ClientHelloIdentifier(reader, nanoShift);
		}
		establishedDtlsContext = DTLSContext.fromReader(reader);
		if (establishedDtlsContext == null) {
			throw new IllegalArgumentException("DTLS Context must not be null!");
		}
		if (reader.readNextByte() == 1) {
			establishedDtlsContext.setReadConnectionId(cid);
		}
		if (reader.bytesAvailable() && reader.readNextByte() == 1) {
			doublePrincipal = true;
		}
		reader.assertFinished("connection");
	}
}
