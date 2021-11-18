/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.config;

import java.net.DatagramSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.config.BasicListDefinition;
import org.eclipse.californium.elements.config.BooleanDefinition;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.ModuleDefinitionsProvider;
import org.eclipse.californium.elements.config.EnumDefinition;
import org.eclipse.californium.elements.config.EnumListDefinition;
import org.eclipse.californium.elements.config.FloatDefinition;
import org.eclipse.californium.elements.config.IntegerDefinition;
import org.eclipse.californium.elements.config.StringSetDefinition;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TimeDefinition;
import org.eclipse.californium.elements.config.ValueException;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.CertificateRequest;
import org.eclipse.californium.scandium.dtls.ExtendedMasterSecretMode;
import org.eclipse.californium.scandium.dtls.HelloVerifyRequest;
import org.eclipse.californium.scandium.dtls.MaxFragmentLengthExtension.Length;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.RecordLayer;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.CertificateKeyAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.dtls.resumption.ResumptionVerifier;

/**
 * Configuration definitions for DTLS.
 * 
 * @since 3.0
 */
public final class DtlsConfig {

	public static final String MODULE = "DTLS.";

	/**
	 * DTLS role.
	 */
	public enum DtlsRole {
		/**
		 * Client only.
		 */
		CLIENT_ONLY,
		/**
		 * Server only.
		 */
		SERVER_ONLY,
		/**
		 * Both roles, client and server.
		 */
		BOTH
	}

	/**
	 * Definition for list of signature and hash algorithms.
	 */
	public static class SignatureAndHashAlgorithmsDefinition extends BasicListDefinition<SignatureAndHashAlgorithm> {

		public SignatureAndHashAlgorithmsDefinition(String key, String documentation) {
			super(key, documentation, null);
		}

		@Override
		public String getTypeName() {
			return "List<SignatureAndHashAlgorithm>";
		}

		@Override
		public String writeValue(List<SignatureAndHashAlgorithm> value) {
			StringBuilder message = new StringBuilder();
			for (SignatureAndHashAlgorithm in : value) {
				message.append(in.getJcaName()).append(", ");
			}
			message.setLength(message.length() - 2);
			return message.toString();
		}

		@Override
		public List<SignatureAndHashAlgorithm> checkValue(List<SignatureAndHashAlgorithm> value) throws ValueException {
			if (value != null) {
				for (SignatureAndHashAlgorithm algorithm : value) {
					if (!algorithm.isSupported()) {
						throw new IllegalArgumentException(algorithm + " is not supported by the JCE!");
					}
				}
			}
			return super.checkValue(value);
		}

		@Override
		protected boolean isAssignableFrom(Object value) {
			if (value instanceof List<?>) {
				for (Object item : (List<?>) value) {
					if (!(item instanceof SignatureAndHashAlgorithm)) {
						throw new IllegalArgumentException(item + " is no SignatureAndHashAlgorithm");
					}
				}
				return true;
			}
			return false;
		}

		@Override
		protected List<SignatureAndHashAlgorithm> parseValue(String value) {
			String[] list = value.split(",");
			List<SignatureAndHashAlgorithm> result = new ArrayList<>(list.length);
			for (String in : list) {
				in = in.trim();
				SignatureAndHashAlgorithm item = SignatureAndHashAlgorithm.valueOf(in);
				result.add(item);
			}
			return result;
		}

	}

	/**
	 * The default value for {@link #DTLS_RETRANSMISSION_TIMEOUT} in
	 * milliseconds.
	 * 
	 * @since 3.0 2s instead of 1s (following ACK timeout in
	 *        <a href="https://tools.ietf.org/html/rfc7252#section-4.8" target=
	 *        "_blank">RFC7252</a>).
	 */
	public static final int DEFAULT_RETRANSMISSION_TIMEOUT_IN_MILLISECONDS = 2000;
	/**
	 * The retransmission timeout according
	 * <a href="https://tools.ietf.org/html/rfc6347#section-4.2.4.1" target=
	 * "_blank">RFC6347</a> in milliseconds.
	 */
	public static final int RFC6347_RETRANSMISSION_TIMEOUT_IN_MILLISECONDS = 1000;
	/**
	 * The retransmission timeout according
	 * <a href="https://tools.ietf.org/html/rfc7925#section-11" target=
	 * "_blank">RFC7925</a> in milliseconds.
	 */
	public static final int RFC7925_RETRANSMISSION_TIMEOUT_IN_MILLISECONDS = 9000;
	/**
	 * The maximum retransmission timeout according
	 * <a href="https://tools.ietf.org/html/rfc6347#section-4.2.4.1" target=
	 * "_blank">RFC6347</a> in milliseconds.
	 */
	public static final int DEFAULT_MAX_RETRANSMISSION_TIMEOUT_IN_MILLISECONDS = 60000;
	/**
	 * The default value for the {@link #DTLS_ADDITIONAL_ECC_TIMEOUT} property
	 * in milliseconds.
	 */
	public static final int DEFAULT_ADDITIONAL_TIMEOUT_FOR_ECC_IN_MILLISECONDS = 0;
	/**
	 * The default value for {@link #DTLS_MAX_RETRANSMISSIONS}.
	 */
	public static final int DEFAULT_MAX_RETRANSMISSIONS = 4;
	/**
	 * The default value for the
	 * {@link #DTLS_MAX_FRAGMENTED_HANDSHAKE_MESSAGE_LENGTH}.
	 */
	public static final int DEFAULT_MAX_FRAGMENTED_HANDSHAKE_MESSAGE_LENGTH = 8192;
	/**
	 * The default value for the {@link #DTLS_MAX_TRANSMISSION_UNIT_LIMIT}
	 * property.
	 */
	public static final int DEFAULT_MAX_TRANSMISSION_UNIT_LIMIT = RecordLayer.DEFAULT_ETH_MTU;
	/**
	 * The default value for the {@link #DTLS_MAX_CONNECTIONS} property.
	 */
	public static final int DEFAULT_MAX_CONNECTIONS = 150000;
	/**
	 * The default value for the {@link #DTLS_STALE_CONNECTION_THRESHOLD}
	 * property in seconds.
	 */
	public static final long DEFAULT_STALE_CONNECTION_TRESHOLD_SECONDS = 30 * 60;
	/**
	 * The default value for the {@link #DTLS_OUTBOUND_MESSAGE_BUFFER_SIZE}
	 * property.
	 */
	public static final int DEFAULT_MAX_PENDING_OUTBOUND_MESSAGES = 100000;
	/**
	 * The default value for the
	 * {@link #DTLS_MAX_DEFERRED_OUTBOUND_APPLICATION_MESSAGES} property.
	 */
	public static final int DEFAULT_MAX_DEFERRED_OUTBOUND_APPLICATION_MESSAGES = 10;
	/**
	 * The default value for the {@link #DTLS_MAX_DEFERRED_INBOUND_RECORDS_SIZE}
	 * property.
	 */
	public static final int DEFAULT_MAX_DEFERRED_PROCESSED_INCOMING_RECORDS_SIZE = 8192;
	/**
	 * The default value for the
	 * {@link #DTLS_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD} property in percent.
	 */
	public static final int DEFAULT_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD_IN_PERCENT = 30;

	/**
	 * DTLS session timeout. Currently not supported!
	 * 
	 * Californium uses {@link #DTLS_MAX_CONNECTIONS} and
	 * {@link #DTLS_STALE_CONNECTION_THRESHOLD} in order to keep session as
	 * along as the resources are not required for fresh connections.
	 */
	public static final TimeDefinition DTLS_SESSION_TIMEOUT = new TimeDefinition(MODULE + "SESSION_TIMEOUT",
			"DTLS session timeout. Currently not supported.", 1L, TimeUnit.HOURS);
	/**
	 * DTLS auto handshake timeout.
	 * 
	 * After that period without exchanged messages, new messages will initiate
	 * a handshake. If possible a resumption/abbreviated handshake is used. Must
	 * not be used with {@link DtlsRole#SERVER_ONLY}. {@code 30s} is a common
	 * value to compensate assumed NAT timeouts.
	 */
	public static final TimeDefinition DTLS_AUTO_HANDSHAKE_TIMEOUT = new TimeDefinition(
			MODULE + "AUTO_HANDSHAKE_TIMEOUT",
			"DTLS auto-handshake timeout. After that period without exchanging messages, "
					+ "a new message will initiate a handshake. Must not be used with SERVER_ONLY! "
					+ "Common value will be \"30[s]\" in order to compensate assumed NAT timeouts. "
					+ "<blank>, disabled.");
	/**
	 * DTLS connection id length.
	 * 
	 * <a href=
	 * "https://tools.ietf.org/html/draft-ietf-tls-dtls-connection-id-06" target
	 * ="_blank"> draft-ietf-tls-dtls-connection-id-06</a>
	 * 
	 * <ul>
	 * <li>{@code ""} disabled support for connection id.</li>
	 * <li>{@code 0} enable support for connection id, but don't use it for
	 * incoming traffic to this peer.</li>
	 * <li>{@code n} use connection id of n bytes. Note: chose n large enough
	 * for the number of considered peers. Recommended to have 100 time more
	 * values than peers. E.g. 65000 peers, chose not 2 bytes, chose at lease 3
	 * bytes!</li>
	 * </ul>
	 */
	public static final IntegerDefinition DTLS_CONNECTION_ID_LENGTH = new IntegerDefinition(
			MODULE + "CONNECTION_ID_LENGTH",
			"DTLS connection ID length. <blank> disabled, 0 enables support without active use of CID.", null, 0);

	/**
	 * If {@link #DTLS_CONNECTION_ID_LENGTH} enables the use of a connection id,
	 * this node id could be used to configure the generation of connection ids
	 * specific for node in a multi-node deployment (cluster). The value is used
	 * as first byte in generated connection ids.
	 */
	public static final IntegerDefinition DTLS_CONNECTION_ID_NODE_ID = new IntegerDefinition(
			MODULE + "CONNECTION_ID_NODE_ID", "DTLS cluster-node ID used for connection ID. <blank> not used.", null,
			0);

	/**
	 * Specify the initial DTLS retransmission timeout.
	 */
	public static final TimeDefinition DTLS_RETRANSMISSION_TIMEOUT = new TimeDefinition(
			MODULE + "RETRANSMISSION_TIMEOUT", "DTLS initial retransmission timeout.",
			DEFAULT_RETRANSMISSION_TIMEOUT_IN_MILLISECONDS, TimeUnit.MILLISECONDS);
	/**
	 * Specify the maximum DTLS retransmission timeout.
	 */
	public static final TimeDefinition DTLS_MAX_RETRANSMISSION_TIMEOUT = new TimeDefinition(
			MODULE + "MAX_RETRANSMISSION_TIMEOUT", "DTLS maximum retransmission timeout.",
			DEFAULT_MAX_RETRANSMISSION_TIMEOUT_IN_MILLISECONDS, TimeUnit.MILLISECONDS);
	/**
	 * Random factor applied to the initial retransmission timeout. Harmonize
	 * CoAP and DTLS.
	 */
	public static final FloatDefinition DTLS_RETRANSMISSION_INIT_RANDOM = new FloatDefinition(
			MODULE + "RETRANSMISSION_INIT_RANDOM", "DTLS random factor for initial retransmission timeout.", 1.0F,
			1.0F);
	/**
	 * Scale factor applied to the retransmission timeout. Harmonize CoAP and
	 * DTLS.
	 */
	public static final FloatDefinition DTLS_RETRANSMISSION_TIMEOUT_SCALE = new FloatDefinition(
			MODULE + "RETRANSMISSION_TIMEOUT_SCALE", "DTLS scale factor for retransmission backoff-timeout.", 2.0F,
			1.0F);
	/**
	 * Specify the additional initial DTLS retransmission timeout, when the
	 * other peer is expected to perform ECC calculations.
	 * 
	 * ECC calculations may be time intensive, especially for smaller
	 * micro-controllers without ecc-hardware support. The additional timeout
	 * prevents Californium from resending a flight too early. The extra time is
	 * used for the DTLS-client, if a ECDSA or ECDHE cipher suite is proposed,
	 * and for the DTLS-server, if a ECDSA or ECDHE cipher suite is selected.
	 * 
	 * This timeout is added to {@link #DTLS_RETRANSMISSION_TIMEOUT} and on each
	 * retransmission, the resulting time is doubled.
	 */
	public static final TimeDefinition DTLS_ADDITIONAL_ECC_TIMEOUT = new TimeDefinition(
			MODULE + "ADDITIONAL_ECC_TIMEOUT", "DTLS additional initial timeout for ECC related flights.",
			DEFAULT_ADDITIONAL_TIMEOUT_FOR_ECC_IN_MILLISECONDS, TimeUnit.MILLISECONDS);
	/**
	 * Specify the maximum number of DTLS retransmissions.
	 */
	public static final IntegerDefinition DTLS_MAX_RETRANSMISSIONS = new IntegerDefinition(
			MODULE + "MAX_RETRANSMISSIONS", "DTLS maximum number of flight retransmissions.",
			DEFAULT_MAX_RETRANSMISSIONS, 0);
	/**
	 * Specify the number of DTLS retransmissions before the attempt to transmit
	 * a flight in back-off mode.
	 * 
	 * <a href="https://tools.ietf.org/html/rfc6347#page-12" target= "_blank">
	 * RFC 6347, Section 4.1.1.1, Page 12</a>
	 * 
	 * In back-off mode, UDP datagrams of maximum 512 bytes or the negotiated
	 * records size, if that is smaller, are used. Each handshake message is
	 * placed in one dtls record, or more dtls records, if the handshake message
	 * is too large and must be fragmented. Beside of the CCS and FINISH dtls
	 * records, which send together in one UDP datagram, all other records are
	 * send in separate datagrams.
	 * 
	 * The {@link #DTLS_USE_MULTI_HANDSHAKE_MESSAGE_RECORDS} and
	 * {@link #DTLS_USE_MULTI_RECORD_MESSAGES} has precedence over the back-off
	 * definition.
	 * 
	 * Value {@code 0}, to disable it, {@code null}, for default of
	 * {@link #DTLS_MAX_RETRANSMISSIONS} / 2.
	 */
	public static final IntegerDefinition DTLS_RETRANSMISSION_BACKOFF = new IntegerDefinition(
			MODULE + "RETRANSMISSION_BACKOFF",
			"Number of flight-retransmissions before switching to backoff mode using single handshake messages in single record datagrams.",
			null, 0);

	/**
	 * Enable or disable the server to use a session ID in order to support or
	 * disable session resumption.
	 */
	public static final BooleanDefinition DTLS_SERVER_USE_SESSION_ID = new BooleanDefinition(
			MODULE + "SERVER_USE_SESSION_ID",
			"Enable server to use a session ID in order to support session resumption.", true);

	/**
	 * Enable early stop of retransmissions. Stop on receiving the first message
	 * of next flight, not waiting for the last.
	 */
	public static final BooleanDefinition DTLS_USE_EARLY_STOP_RETRANSMISSION = new BooleanDefinition(
			MODULE + "USE_EARLY_STOP_RETRANSMISSION",
			"Stop retransmission on receiving the first message of the next flight, not waiting for the last message.",
			true);

	/**
	 * Specify the record size limit.
	 * 
	 * See <a href="https://tools.ietf.org/html/rfc8449" target="_blank">RFC
	 * 8449</a> for details.
	 */
	public static final IntegerDefinition DTLS_RECORD_SIZE_LIMIT = new IntegerDefinition(MODULE + "RECORD_SIZE_LIMIT",
			"DTLS record size limit (RFC 8449). Between 64 and 65535.", null, 64);

	/**
	 * Specify the maximum fragment length.
	 * 
	 * See <a href="https://tools.ietf.org/html/rfc6066#section-4" target=
	 * "_blank">RFC 6066, Section 4</a> for details.
	 */
	public static final EnumDefinition<Length> DTLS_MAX_FRAGMENT_LENGTH = new EnumDefinition<>(
			MODULE + "MAX_FRAGMENT_SIZE", "DTLS maximum fragment length (RFC 6066).", Length.values());

	/**
	 * Specify the maximum length of reassembled fragmented handshake messages.
	 */
	public static final IntegerDefinition DTLS_MAX_FRAGMENTED_HANDSHAKE_MESSAGE_LENGTH = new IntegerDefinition(
			MODULE + "MAX_FRAGMENTED_HANDSHAKE_MESSAGE_LENGTH",
			"DTLS maximum length of reassembled fragmented handshake message.\n" +
			"Must be large enough for used certificates.",
			DEFAULT_MAX_FRAGMENTED_HANDSHAKE_MESSAGE_LENGTH, 64);

	/**
	 * Enable to use multiple DTLS records in UDP messages.
	 */
	public static final BooleanDefinition DTLS_USE_MULTI_RECORD_MESSAGES = new BooleanDefinition(
			MODULE + "USE_MULTI_RECORD_MESSAGES", "Use multiple DTLS records in UDP messages.");
	/**
	 * Enable to use multiple DTLS records in UDP messages.
	 */
	public static final BooleanDefinition DTLS_USE_MULTI_HANDSHAKE_MESSAGE_RECORDS = new BooleanDefinition(
			MODULE + "USE_MULTI_HANDSHAKE_MESSAGE_RECORDS",
			"Use multiple handshake messages in DTLS records.\nNot all libraries may have implemented this!");

	/**
	 * Specify the client's certificate authentication mode.
	 * 
	 * Used on the server-side to request a client certificate for
	 * authentication.
	 */
	public static final EnumDefinition<CertificateAuthenticationMode> DTLS_CLIENT_AUTHENTICATION_MODE = new EnumDefinition<>(
			MODULE + "CLIENT_AUTHENTICATION_MODE",
			"DTLS client authentication mode for certificate based cipher suites.",
			CertificateAuthenticationMode.NEEDED, CertificateAuthenticationMode.values());

	/**
	 * Enable the DTLS client to verify the server certificate's subjects.
	 */
	public static final BooleanDefinition DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT = new BooleanDefinition(
			MODULE + "VERIFY_SERVER_CERTIFICATES_SUBJECT", "DTLS verifies the server certificate's subjects.", true);

	/**
	 * Specify the supported DTLS roles.
	 */
	public static final EnumDefinition<DtlsRole> DTLS_ROLE = new EnumDefinition<>(MODULE + "ROLE", "DTLS role.",
			DtlsRole.BOTH, DtlsRole.values());

	/**
	 * Specify the MTU (Maximum Transmission Unit).
	 */
	public static final IntegerDefinition DTLS_MAX_TRANSMISSION_UNIT = new IntegerDefinition(
			MODULE + "MAX_TRANSMISSION_UNIT", "DTLS MTU (Maximum Transmission Unit).", null, 64);

	/**
	 * Specify a MTU (Maximum Transmission Unit) limit for (link local) auto
	 * detection.
	 * 
	 * Limits maximum number of bytes sent in one transmission.
	 *
	 * Note: previous versions took the local link MTU without limits. That
	 * results in possibly larger MTU, e.g. for localhost or some cloud nodes
	 * using "jumbo frames". If a larger MTU is required, please adjust this
	 * limit to the requires value or use {@link #DEFAULT_MAX_RETRANSMISSIONS}.
	 */
	public static final IntegerDefinition DTLS_MAX_TRANSMISSION_UNIT_LIMIT = new IntegerDefinition(
			MODULE + "MAX_TRANSMISSION_UNIT_LIMIT",
			"DTLS MTU (Maximum Transmission Unit) limit for local auto detection.", null, 64);

	/**
	 * Specify default handshake mode.
	 * 
	 * <b>Note:</b> if {@link #DTLS_ROLE} is {@link DtlsRole#SERVER_ONLY}, the
	 * specified default handshake mode is ignored and replaced by
	 * {@link DtlsEndpointContext#HANDSHAKE_MODE_NONE}.
	 * 
	 * Values are {@link DtlsEndpointContext#HANDSHAKE_MODE_NONE} or
	 * {@link DtlsEndpointContext#HANDSHAKE_MODE_AUTO}.
	 */
	public static final StringSetDefinition DTLS_DEFAULT_HANDSHAKE_MODE = new StringSetDefinition(
			MODULE + "DEFAULT_HANDSHAKE_MODE", "DTLS default handshake mode.", DtlsEndpointContext.HANDSHAKE_MODE_AUTO,
			DtlsEndpointContext.HANDSHAKE_MODE_NONE, DtlsEndpointContext.HANDSHAKE_MODE_AUTO);

	/**
	 * Specify the maximum number of active connections the connector should
	 * support.
	 * <p>
	 * An <em>active</em> connection is a connection that has been used within
	 * the last <em>staleConnectionThreshold</em> seconds. After that it is
	 * considered to be <em>stale</em>.
	 * <p>
	 * Once the maximum number of active connections is reached, new connections
	 * will only be accepted by the connector, if <em>stale</em> connections
	 * exist (which will be evicted one-by-one on an oldest-first basis).
	 * <p>
	 * The default value of this property is {@link #DEFAULT_MAX_CONNECTIONS}.
	 */
	public static final IntegerDefinition DTLS_MAX_CONNECTIONS = new IntegerDefinition(MODULE + "MAX_CONNECTIONS",
			"DTLS maximum connections.", DEFAULT_MAX_CONNECTIONS, 1);

	/**
	 * Specify the threshold without any data being exchanged before a
	 * connection is considered <em>stale</em>.
	 * <p>
	 * Once a connection becomes stale, it is eligible for eviction when a peer
	 * wants to establish a new connection and the connector already has
	 * {@link #DTLS_MAX_CONNECTIONS} connections with peers established.
	 * <p>
	 * <b>Note:</b> a connection is no longer considered stale, once data is
	 * being exchanged over it before it got evicted.
	 */
	public static final TimeDefinition DTLS_STALE_CONNECTION_THRESHOLD = new TimeDefinition(
			MODULE + "STALE_CONNECTION_THRESHOLD",
			"DTLS threshold for state connections. Connections will only get removed for new ones, "+
			"if at least for that threshold no messages are exchanged using that connection.",
			DEFAULT_STALE_CONNECTION_TRESHOLD_SECONDS, TimeUnit.SECONDS);

	/**
	 * Specify the number of outbound messages that can be buffered in memory
	 * before dropping messages.
	 */
	public static final IntegerDefinition DTLS_OUTBOUND_MESSAGE_BUFFER_SIZE = new IntegerDefinition(
			MODULE + "OUTBOUND_MESSAGE_BUFFER_SIZE", "DTLS buffer size for outbound messages.",
			DEFAULT_MAX_PENDING_OUTBOUND_MESSAGES, 64);

	/**
	 * Specify maximum number of deferred processed outgoing application data
	 * messages.
	 * 
	 * Application data messages sent during a handshake may be dropped or
	 * processed deferred after the handshake. Set this to limit the maximum
	 * number of messages, which are intended to be processed deferred. If more
	 * messages are sent, these messages are dropped.
	 */
	public static final IntegerDefinition DTLS_MAX_DEFERRED_OUTBOUND_APPLICATION_MESSAGES = new IntegerDefinition(
			MODULE + "MAX_DEFERRED_OUTBOUND_APPLICATION_MESSAGES",
			"DTLS maximum deferred outbound application messages.",
			DEFAULT_MAX_DEFERRED_OUTBOUND_APPLICATION_MESSAGES, 0);
	/**
	 * Specify maximum size of deferred processed incoming records.
	 * 
	 * Handshake records with future handshake message sequence number or
	 * records with future epochs received during a handshake may be dropped or
	 * processed deferred. Set this to limit the maximum size of all records,
	 * which are intended to be processed deferred. If more records are
	 * received, these records are dropped.
	 */
	public static final IntegerDefinition DTLS_MAX_DEFERRED_INBOUND_RECORDS_SIZE = new IntegerDefinition(
			MODULE + "MAX_DEFERRED_INBOUND_RECORDS", "DTLS maximum size of all deferred inbound messages.",
			DEFAULT_MAX_DEFERRED_PROCESSED_INCOMING_RECORDS_SIZE, 0);

	/**
	 * Specify the number of receiver threads used by a {@link DTLSConnector}.
	 * The receiver threads are responsible for receiving the messages and
	 * parsing them into structured {@link Record}s. Cryptographic function
	 * except the cookie generation for {@link HelloVerifyRequest} are not
	 * executed by this thread, these are executed by
	 * {@link #DTLS_CONNECTOR_THREAD_COUNT}.
	 */
	public static final IntegerDefinition DTLS_RECEIVER_THREAD_COUNT = new IntegerDefinition(
			MODULE + "RECEIVER_THREAD_COUNT", "Number of DTLS receiver threads.", 1, 0);
	/**
	 * Specify the number of connector threads used by a {@link DTLSConnector}.
	 * The connector threads are responsible for the most cryptographic
	 * functions for both incoming and outgoing messages.
	 */
	public static final IntegerDefinition DTLS_CONNECTOR_THREAD_COUNT = new IntegerDefinition(
			MODULE + "CONNECTOR_THREAD_COUNT", "Number of DTLS connector threads.", 1, 0);
	/**
	 * Specify the DTLS receive buffer size used for
	 * {@link DatagramSocket#setReceiveBufferSize(int)}.
	 */
	public static final IntegerDefinition DTLS_RECEIVE_BUFFER_SIZE = new IntegerDefinition(
			MODULE + "RECEIVE_BUFFER_SIZE", "DTLS receive-buffer size.", null, 64);
	/**
	 * Specify the DTLS send buffer size used for
	 * {@link DatagramSocket#setSendBufferSize(int)}.
	 */
	public static final IntegerDefinition DTLS_SEND_BUFFER_SIZE = new IntegerDefinition(MODULE + "SEND_BUFFER_SIZE",
			"DTLS send-buffer size.", null, 64);

	/**
	 * Specify the usage and support of "server name indication".
	 * 
	 * The support on the server side currently includes a server name specific
	 * PSK secret lookup and to forward the server name to the CoAP stack in the
	 * {@link org.eclipse.californium.elements.EndpointContext}.
	 * 
	 * See <a href="https://tools.ietf.org/html/rfc6066#section-3" target=
	 * "_blank">RFC 6066, Section 3</a>
	 */
	public static final BooleanDefinition DTLS_USE_SERVER_NAME_INDICATION = new BooleanDefinition(
			MODULE + "USE_SERVER_NAME_INDICATION", "DTLS use server name indication.", false);

	/**
	 * Defines the usage of the "extend master secret" extension.
	 * 
	 * See <a href="https://tools.ietf.org/html/rfc7627" target="_blank">RFC
	 * 7627</a>
	 */
	public static final EnumDefinition<ExtendedMasterSecretMode> DTLS_EXTENDED_MASTER_SECRET_MODE = new EnumDefinition<>(
			MODULE + "EXTENDED_MASTER_SECRET_MODE", "DTLS extended master secret mode.",
			ExtendedMasterSecretMode.ENABLED, ExtendedMasterSecretMode.values());

	/**
	 * Threshold of pending handshakes without verified peer for session
	 * resumption in percent of {@link #DTLS_MAX_CONNECTIONS}. If more such
	 * handshakes are pending, then use a verify request to ensure, that the
	 * used client hello is not spoofed.
	 * 
	 * <pre>
	 * 0 := always use a HELLO_VERIFY_REQUEST
	 * 1 ... 100 := dynamically determine to use a HELLO_VERIFY_REQUEST.
	 * </pre>
	 * 
	 * Peers are identified by their endpoint (ip-address and port). To protect
	 * the server from congestion by address spoofing, a HELLO_VERIFY_REQUEST is
	 * used. That adds one exchange and with that, additional latency. In cases
	 * of session resumption, the server may also use the dtls session ID as a
	 * weaker proof of a valid client. Unfortunately there are several
	 * elaborated attacks to that (e.g. on-path-attacker may alter the
	 * source-address). To mitigate this vulnerability, this threshold defines a
	 * maximum percentage of handshakes without HELLO_VERIFY_REQUEST. If more
	 * resumption handshakes without verified peers are pending than this
	 * threshold, then a HELLO_VERIFY_REQUEST is used again. Additionally, if a
	 * peer resumes a session (by id), but a different session is related to its
	 * endpoint, then a verify request is used to ensure, that the peer really
	 * owns that endpoint.
	 * <p>
	 * <b>Note:</b> a value larger than 0 will call the
	 * {@link ResumptionVerifier}. If that implementation is expensive, please
	 * ensure, that this value is configured with {@code 0}. Otherwise,
	 * CLIENT_HELLOs with invalid session IDs may be spoofed and gets too
	 * expensive.
	 * </p>
	 * <p>
	 * <b>Note:</b> if spoofing is considered to be relevant for the used
	 * network environment, please set this to {@code 0} using
	 * {@link Builder#set} with
	 * {@link DtlsConfig#DTLS_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD} in order to
	 * disable this function.
	 * </p>
	 * Default {@link #DEFAULT_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD_IN_PERCENT}.
	 */
	public static final IntegerDefinition DTLS_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD = new IntegerDefinition(
			MODULE + "VERIFY_PEERS_ON_RESUMPTION_THRESHOLD", "DTLS verify peers on resumption threshold in percent.",
			DEFAULT_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD_IN_PERCENT, 0);
	/**
	 * Enable/Disable the server's HELLO_VERIFY_REQUEST, if peers shares at
	 * least one PSK based cipher suite.
	 * <p>
	 * <b>Note:</b> it is not recommended to disable the HELLO_VERIFY_REQUEST!
	 * See <a href="https://tools.ietf.org/html/rfc6347#section-4.2.1" target=
	 * "_blank">RFC 6347, 4.2.1. Denial-of-Service Countermeasures</a>.
	 * </p>
	 * To limit the amplification, the peers must share PSK cipher suites to by
	 * pass that check. If only certificate based cipher suites are shared, the
	 * HELLO_VERIFY_REQUEST will still be used.
	 * 
	 */
	public static final BooleanDefinition DTLS_USE_HELLO_VERIFY_REQUEST_FOR_PSK = new BooleanDefinition(
			MODULE + "USE_HELLO_VERIFY_REQUEST_FOR_PSK",
			"DTLS use a HELLO_VERIFY_REQUEST for PSK cipher suites to protect against spoofing.", true);
	/**
	 * Generally enable/disable the server's HELLO_VERIFY_REQUEST.
	 * <p>
	 * <b>Note:</b> it is strongly not recommended to disable the
	 * HELLO_VERIFY_REQUEST if used with certificates! That creates a large
	 * amplification! See
	 * <a href="https://tools.ietf.org/html/rfc6347#section-4.2.1" target=
	 * "_blank">RFC 6347, 4.2.1. Denial-of-Service Countermeasures</a>.
	 * </p>
	 */
	public static final BooleanDefinition DTLS_USE_HELLO_VERIFY_REQUEST = new BooleanDefinition(
			MODULE + "USE_HELLO_VERIFY_REQUEST", "DTLS use a HELLO_VERIFY_REQUESt to protect against spoofing.", true);

	/**
	 * Use anti replay filter.
	 * 
	 * @see <a href= "https://tools.ietf.org/html/rfc6347#section-4.1.2.6"
	 *      target= "_blank">RFC6347 4.1.2.6. Anti-Replay</a>
	 */
	public static final BooleanDefinition DTLS_USE_ANTI_REPLAY_FILTER = new BooleanDefinition(
			MODULE + "USE_USE_ANTI_REPLAY_FILTER", "DTLS use the anti-replay-filter.", true);

	/**
	 * Use disabled window for anti replay filter.
	 * 
	 * Californium uses the "sliding receive window" approach mentioned in
	 * <a href= "https://tools.ietf.org/html/rfc6347#section-4.1.2.6" target=
	 * "_blank">RFC6347 4.1.2.6. Anti-Replay</a>. That causes trouble, if some
	 * records are sent on postponed routes (e.g. SMS). That would make it more
	 * probable, that the record is to old for the receive window. In order not
	 * to discard such records, this values defines a "disabled window", that
	 * allows record to pass the filter, even if the records are too old for the
	 * current receive window.
	 * 
	 * The configured value will be subtracted from to lower receive window
	 * boundary. A value of {@code -1} will set that calculated lower boundary
	 * to {@code 0}. Messages between lower receive window boundary and that
	 * calculated value will pass the filter, for other messages the filter is
	 * applied.
	 * 
	 * @see <a href= "https://tools.ietf.org/html/rfc6347#section-4.1.2.6"
	 *      target= "_blank">RFC6347 4.1.2.6. Anti-Replay</a>
	 */
	public static final IntegerDefinition DTLS_USE_DISABLED_WINDOW_FOR_ANTI_REPLAY_FILTER = new IntegerDefinition(
			MODULE + "USE_DISABLED_WINDOW_FOR_ANTI_REPLAY_FILTER",
			"DTLS use a disabled window for the anti-replay-filter. -1 := extend the disabled window to start of session, 0 := normal window, <n> := disabled window of size <n>.",
			0, -1);
	/**
	 * Update the ip-address from DTLS 1.2 CID records only for newer records
	 * based on epoch/sequence_number.
	 * 
	 * @see <a href=
	 *      "https://tools.ietf.org/html/draft-ietf-tls-dtls-connection-id#section-6"
	 *      target= "_blank">Draft Connection Identifiers for DTLS 1.2, 6. Peer
	 *      Address Update</a>
	 */
	public static final BooleanDefinition DTLS_UPDATE_ADDRESS_USING_CID_ON_NEWER_RECORDS = new BooleanDefinition(
			MODULE + "UPDATE_ADDRESS_USING_CID_ON_NEWER_RECORDS", "DTLS update address using CID on newer records.",
			true);

	/**
	 * Use truncated certificate paths for client's certificate message.
	 * 
	 * Truncate certificate path according the received certificate authorities
	 * in the {@link CertificateRequest} for the client's
	 * {@link CertificateMessage}.
	 */
	public static final BooleanDefinition DTLS_TRUNCATE_CLIENT_CERTIFICATE_PATH = new BooleanDefinition(
			MODULE + "TRUNCATE_CLIENT_CERTIFICATE_PATH", "DTLS truncate client certificate path.", true);

	/**
	 * Use truncated certificate paths for validation.
	 * 
	 * Truncate certificate path according the available trusted certificates
	 * before validation.
	 */
	public static final BooleanDefinition DTLS_TRUNCATE_CERTIFICATE_PATH_FOR_VALIDATION = new BooleanDefinition(
			MODULE + "TRUNCATE_CERTIFICATE_PATH_FOR_VALIDATION", "DTLS certificate path for validation.", true);

	/**
	 * Use recommended {@link CipherSuite}s only.
	 * 
	 * @see CipherSuite#isRecommended()
	 */
	public static final BooleanDefinition DTLS_RECOMMENDED_CIPHER_SUITES_ONLY = new BooleanDefinition(
			MODULE + "RECOMMENDED_CIPHER_SUITES_ONLY", "DTLS recommended cipher-suites only.", true);
	/**
	 * Use recommended {@link SupportedGroup}s only.
	 * 
	 * @see SupportedGroup#isRecommended()
	 */
	public static final BooleanDefinition DTLS_RECOMMENDED_CURVES_ONLY = new BooleanDefinition(
			MODULE + "RECOMMENDED_CURVES_ONLY", "DTLS recommended ECC curves/groups only.", true);
	/**
	 * Use recommended {@link SignatureAndHashAlgorithm}s only.
	 * 
	 * @see SignatureAndHashAlgorithm#isRecommended()
	 */
	public static final BooleanDefinition DTLS_RECOMMENDED_SIGNATURE_AND_HASH_ALGORITHMS_ONLY = new BooleanDefinition(
			MODULE + "RECOMMENDED_SIGNATURE_AND_HASH_ALGORITHMS_ONLY",
			"DTLS recommended signature- and hash-algorithms only.", true);

	/**
	 * Preselected {@link CipherSuite}s.
	 */
	public static final EnumListDefinition<CipherSuite> DTLS_PRESELECTED_CIPHER_SUITES = new EnumListDefinition<>(
			MODULE + "PRESELECTED_CIPHER_SUITES",
			"List of preselected DTLS cipher-suites.\n" +
			"If not recommended cipher suites are intended to be used, switch off DTLS_RECOMMENDED_CIPHER_SUITES_ONLY.\n" +
			"The supported cipher suites are evaluated at runtime and may differ from the ones when creating this properties file.",
			CipherSuite.getCipherSuites(false, false));
	/**
	 * Select {@link CipherSuite}s.
	 */
	public static final EnumListDefinition<CipherSuite> DTLS_CIPHER_SUITES = new EnumListDefinition<>(
			MODULE + "CIPHER_SUITES",
			"List of DTLS cipher-suites.\n" +
			"If not recommended cipher suites are intended to be used, switch off DTLS_RECOMMENDED_CIPHER_SUITES_ONLY.\n" +
			"The supported cipher suites are evaluated at runtime and may differ from the ones when creating this properties file.",
			null, 1, CipherSuite.getCipherSuites(false, true));
	/**
	 * Select curves ({@link SupportedGroup}s).
	 */
	public static final EnumListDefinition<SupportedGroup> DTLS_CURVES = new EnumListDefinition<>(MODULE + "CURVES",
			"List of DTLS curves (supported groups).\nDefaults to all supported curves of the JCE at runtime.",
			SupportedGroup.getUsableGroupsArray());
	/**
	 * Select ({@link SignatureAndHashAlgorithm}s).
	 */
	public static final SignatureAndHashAlgorithmsDefinition DTLS_SIGNATURE_AND_HASH_ALGORITHMS = new SignatureAndHashAlgorithmsDefinition(
			MODULE + "SIGNATURE_AND_HASH_ALGORITHMS",
			"List of DTLS signature- and hash-algorithms.\nValues e.g SHA256withECDSA or ED25519.");
	/**
	 * Select {@link CertificateKeyAlgorithm}s.
	 */
	public static final EnumListDefinition<CertificateKeyAlgorithm> DTLS_CERTIFICATE_KEY_ALGORITHMS = new EnumListDefinition<>(
			MODULE + "CERTIFICATE_KEY_ALGORITHMS",
			"List of DTLS certificate key algorithms.\n" +
			"On the client side used to select the default cipher-suites, on the server side to negotiate the client's certificate.",
			new CertificateKeyAlgorithm[] { CertificateKeyAlgorithm.EC, CipherSuite.CertificateKeyAlgorithm.RSA });

	/**
	 * Specify the usage of DTLS CID before version 09 of <a href=
	 * "https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id/"
	 * target="_blank">Draft dtls-connection-id</a> for the client side.
	 */
	public static final IntegerDefinition DTLS_USE_DEPRECATED_CID = new IntegerDefinition(MODULE + "USE_DEPRECATED_CID",
			"DTLS use deprecated CID extension code point for client (before version 09 of RFC-CID).", null, 53);
	/**
	 * Specify the support of DTLS CID before version 9 of <a href=
	 * "https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id/"
	 * target="_blank">Draft dtls-connection-id</a> for the server side.
	 */
	public static final BooleanDefinition DTLS_SUPPORT_DEPRECATED_CID = new BooleanDefinition(
			MODULE + "SUPPORT_DEPRECATED_CID", "DTLS support deprecated CID for server (before version 9).", false);

	public static final ModuleDefinitionsProvider DEFINITIONS = new ModuleDefinitionsProvider() {

		@Override
		public String getModule() {
			return MODULE;
		}

		@Override
		public void applyDefinitions(Configuration config) {
			final int CORES = Runtime.getRuntime().availableProcessors();

			config.set(DTLS_SESSION_TIMEOUT, 24, TimeUnit.HOURS);
			config.set(DTLS_AUTO_HANDSHAKE_TIMEOUT, null, TimeUnit.SECONDS);
			config.set(DTLS_RETRANSMISSION_TIMEOUT, DEFAULT_RETRANSMISSION_TIMEOUT_IN_MILLISECONDS,
					TimeUnit.MILLISECONDS);
			config.set(DTLS_MAX_RETRANSMISSION_TIMEOUT, DEFAULT_MAX_RETRANSMISSION_TIMEOUT_IN_MILLISECONDS,
					TimeUnit.MILLISECONDS);
			config.set(DTLS_ADDITIONAL_ECC_TIMEOUT, DEFAULT_ADDITIONAL_TIMEOUT_FOR_ECC_IN_MILLISECONDS,
					TimeUnit.MILLISECONDS);
			config.set(DTLS_MAX_RETRANSMISSIONS, DEFAULT_MAX_RETRANSMISSIONS);
			config.set(DTLS_RETRANSMISSION_INIT_RANDOM, 1.0F);
			config.set(DTLS_RETRANSMISSION_TIMEOUT_SCALE, 2.0F);
			config.set(DTLS_RETRANSMISSION_BACKOFF, null);
			config.set(DTLS_CONNECTION_ID_LENGTH, null);
			config.set(DTLS_CONNECTION_ID_NODE_ID, null);
			config.set(DTLS_SERVER_USE_SESSION_ID, true);
			config.set(DTLS_USE_EARLY_STOP_RETRANSMISSION, true);
			config.set(DTLS_RECORD_SIZE_LIMIT, null);
			config.set(DTLS_MAX_FRAGMENT_LENGTH, null);
			config.set(DTLS_MAX_FRAGMENTED_HANDSHAKE_MESSAGE_LENGTH, DEFAULT_MAX_FRAGMENTED_HANDSHAKE_MESSAGE_LENGTH);
			config.set(DTLS_USE_MULTI_RECORD_MESSAGES, null);
			config.set(DTLS_USE_MULTI_HANDSHAKE_MESSAGE_RECORDS, null);
			config.set(DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NEEDED);
			config.set(DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, true);
			config.set(DTLS_ROLE, DtlsRole.BOTH);
			config.set(DTLS_MAX_TRANSMISSION_UNIT, null);
			config.set(DTLS_MAX_TRANSMISSION_UNIT_LIMIT, DEFAULT_MAX_TRANSMISSION_UNIT_LIMIT);
			config.set(DTLS_DEFAULT_HANDSHAKE_MODE, null);
			config.set(DTLS_MAX_CONNECTIONS, DEFAULT_MAX_CONNECTIONS);
			config.set(DTLS_STALE_CONNECTION_THRESHOLD, DEFAULT_STALE_CONNECTION_TRESHOLD_SECONDS, TimeUnit.SECONDS);
			config.set(DTLS_OUTBOUND_MESSAGE_BUFFER_SIZE, DEFAULT_MAX_PENDING_OUTBOUND_MESSAGES);
			config.set(DTLS_MAX_DEFERRED_OUTBOUND_APPLICATION_MESSAGES,
					DEFAULT_MAX_DEFERRED_OUTBOUND_APPLICATION_MESSAGES);
			config.set(DTLS_MAX_DEFERRED_INBOUND_RECORDS_SIZE, DEFAULT_MAX_DEFERRED_PROCESSED_INCOMING_RECORDS_SIZE);

			config.set(DTLS_RECEIVER_THREAD_COUNT, CORES > 3 ? 2 : 1);
			config.set(DTLS_CONNECTOR_THREAD_COUNT, CORES);
			config.set(DTLS_RECEIVE_BUFFER_SIZE, null);
			config.set(DTLS_SEND_BUFFER_SIZE, null);
			config.set(DTLS_USE_SERVER_NAME_INDICATION, false);
			config.set(DTLS_EXTENDED_MASTER_SECRET_MODE, ExtendedMasterSecretMode.ENABLED);
			config.set(DTLS_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD,
					DEFAULT_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD_IN_PERCENT);
			config.set(DTLS_USE_HELLO_VERIFY_REQUEST, true);
			config.set(DTLS_USE_HELLO_VERIFY_REQUEST_FOR_PSK, true);
			config.set(DTLS_USE_ANTI_REPLAY_FILTER, true);
			config.set(DTLS_USE_DISABLED_WINDOW_FOR_ANTI_REPLAY_FILTER, 0);
			config.set(DTLS_UPDATE_ADDRESS_USING_CID_ON_NEWER_RECORDS, true);
			config.set(DTLS_TRUNCATE_CLIENT_CERTIFICATE_PATH, true);
			config.set(DTLS_TRUNCATE_CERTIFICATE_PATH_FOR_VALIDATION, true);
			config.set(DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, true);
			config.set(DTLS_RECOMMENDED_CURVES_ONLY, true);
			config.set(DTLS_RECOMMENDED_SIGNATURE_AND_HASH_ALGORITHMS_ONLY, true);
			config.set(DTLS_PRESELECTED_CIPHER_SUITES, null);
			config.set(DTLS_CIPHER_SUITES, null);
			config.set(DTLS_CURVES, null);
			config.set(DTLS_SIGNATURE_AND_HASH_ALGORITHMS, null);
			config.set(DTLS_CERTIFICATE_KEY_ALGORITHMS, null);
			config.set(DTLS_USE_DEPRECATED_CID, null);
			config.set(DTLS_SUPPORT_DEPRECATED_CID, false);
		}
	};

	static {
		Configuration.addDefaultModule(DEFINITIONS);
	}

	/**
	 * Register definitions of this module to the default definitions. Register
	 * the required definitions of {@link SystemConfig} as well.
	 */
	public static void register() {
		SystemConfig.register();
	}
}
