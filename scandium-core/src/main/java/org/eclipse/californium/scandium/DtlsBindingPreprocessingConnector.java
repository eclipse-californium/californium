/*******************************************************************************
 * Copyright (c) 2022 AVSystem and others.
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
 *    Jakub Pinowski (AVSystem) - initial creation
 ******************************************************************************/

package org.eclipse.californium.scandium;

import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.ResumptionSupportingConnectionStore;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.Executor;

/**
 * DTLS connector with customizable preprocessing of a connection binding.
 * <p>
 * Provides a way to perform external preprocessing using source socket address
 * and connection ID before DTLSConnector's internal connection store
 * is accessed.
 * </p>
 * <p>
 * Example of usage; simple reading and restoring connection from shared storage.
 * This code uses a separate ForkJoinPool to execute its action in order to release connector's
 * receiver threads in case of some complex operations (reading from map is here to
 * just show the concept).
 * </p>
 * <p>
 * Lambda syntax [<b>(...) -&gt; {}</b>] requires Java 8 or newer.
 * </p>
 * <pre>
 * {@code
 * final Set<ConnectionId> knownCids = new HashSet<>();
 * final Map<ConnectionId, Connection> mockedDb = new HashMap<>();
 * final ForkJoinPool pool = new ForkJoinPool();
 * DtlsBindingPreprocessingConnector connector = new DtlsBindingPreprocessingConnector(...);
 * connector.setBeforeConnectionRetrievalAction((cid, addr, callback) -> {
 * 	if (cid != null) {
 * 		pool.execute(() -> {
 * 			if (!knownCids.contains(cid)) {
 * 				Connection conn = mockedDb.get(cid);
 * 				if (conn != null) {
 * 					connector.restoreConnection(conn);
 * 					knownCids.add(cid);
 * 				}
 * 			}
 * 			callback.run();
 * 		});
 * 	} else {
 * 		callback.run();
 * 	}
 * });
 * }
 * </pre>
 *
 * @since 3.6
 */
public class DtlsBindingPreprocessingConnector extends DTLSConnector {

	/**
	 * Interface to inject preprocessing logic
	 * <p>
	 * <b>CAUTIONS:</b>
	 * </p>
	 * <p>
	 * {@link DtlsBindingActionWithCallback} implementation must call {@code callback.run()}
	 * in order to continue records processing.
	 * </p>
	 * <p>
	 * If created action is running on separate threads, consider limiting such pending jobs in order
	 * to protect against DoS attack. Similar approach may be seen in
	 * {@link DTLSConnector#executeInbound(Executor, InetSocketAddress, org.eclipse.californium.elements.util.LimitedRunnable)}
	 * </p>
	 */
	public interface DtlsBindingActionWithCallback {
		/**
		 * @param cid DTLS connection ID.
		 * @param addr Source address of the received datagram.
		 * @param callback Connector's action to be called in order
		 *                 to continue records processing.
		 */
		void run(ConnectionId cid, InetSocketAddress addr, Runnable callback);
	}

	private final static DtlsBindingActionWithCallback defaultAction = new DtlsBindingActionWithCallback() {
		@Override
		public void run(ConnectionId cid, InetSocketAddress addr, Runnable callback) {
			callback.run();
		}
	};

	private DtlsBindingActionWithCallback beforeConnectionRetrievalAction = defaultAction;

	/**
	 * @see DTLSConnector#DTLSConnector(DtlsConnectorConfig)
	 * @param configuration The configuration options.
	 */
	public DtlsBindingPreprocessingConnector(DtlsConnectorConfig configuration) {
		super(configuration);
	}

	/**
	 * @see DTLSConnector#DTLSConnector(DtlsConnectorConfig, ResumptionSupportingConnectionStore)
	 * @param configuration The configuration options.
	 * @param connectionStore The registry to use for managing connections to peers.
	 */
	public DtlsBindingPreprocessingConnector(DtlsConnectorConfig configuration, ResumptionSupportingConnectionStore connectionStore) {
		super(configuration, connectionStore);
	}

	/**
	 * Set an action invoked on every received DTLS datagram, before internal connection store is accessed.
	 * It may be used to inject some synchronous or asynchronous action.
	 *
	 * @param beforeConnectionRetrievalAction Action to be executed
	 * @throws IllegalStateException If connector is currently running
	 */
	synchronized public void setBeforeConnectionRetrievalAction(DtlsBindingActionWithCallback beforeConnectionRetrievalAction) {
		if (this.beforeConnectionRetrievalAction != beforeConnectionRetrievalAction) {
			if (isRunning()) {
				throw new IllegalStateException("cannot set action while connector is running");
			} else {
				if (beforeConnectionRetrievalAction == null) {
					this.beforeConnectionRetrievalAction = defaultAction;
				} else {
					this.beforeConnectionRetrievalAction = beforeConnectionRetrievalAction;
				}
			}
		}
	}

	@Override
	protected void processRecords(final List<Record> records,
								  final InetSocketAddress peerAddress,
								  final InetSocketAddress router) {
		ConnectionId connectionId = records.get(0).getConnectionId();
		beforeConnectionRetrievalAction.run(connectionId, peerAddress, new Runnable() {
			@Override
			public void run() {
				processRecordsInternally(records, peerAddress, router);
			}
		});
	}

	private void processRecordsInternally(List<Record> records, InetSocketAddress peerAddress, InetSocketAddress router) {
		super.processRecords(records, peerAddress, router);
	}
}
