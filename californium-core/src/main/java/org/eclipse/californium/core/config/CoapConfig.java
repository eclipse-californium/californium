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
 *    Bosch IO.GmbH - initial creation (derived from former NetworkConfig)
 ******************************************************************************/
package org.eclipse.californium.core.config;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.GroupedMessageIdTracker;
import org.eclipse.californium.core.network.KeyMID;
import org.eclipse.californium.core.network.KeyToken;
import org.eclipse.californium.core.network.TokenGenerator;
import org.eclipse.californium.core.network.deduplication.CropRotation;
import org.eclipse.californium.core.network.deduplication.NoDeduplicator;
import org.eclipse.californium.core.network.deduplication.SweepDeduplicator;
import org.eclipse.californium.core.network.deduplication.SweepPerPeerDeduplicator;
import org.eclipse.californium.core.network.stack.KeyUri;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.elements.EndpointIdentityResolver;
import org.eclipse.californium.elements.config.BooleanDefinition;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.DefinitionUtils;
import org.eclipse.californium.elements.config.Configuration.ModuleDefinitionsProvider;
import org.eclipse.californium.elements.config.EnumDefinition;
import org.eclipse.californium.elements.config.FloatDefinition;
import org.eclipse.californium.elements.config.IntegerDefinition;
import org.eclipse.californium.elements.config.StringSetDefinition;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TimeDefinition;

/**
 * Configuration definitions for CoAP.
 * 
 * Used for a Californium's server, endpoint and/or connector.
 * 
 * @since 3.0 (derived from former NetworkConfig)
 */
public final class CoapConfig {

	public static final String MODULE = "COAP.";

	/**
	 * Matcher mode.
	 * 
	 * Used for UDP and DTLS.
	 */
	public enum MatcherMode {
		/**
		 * Strict matching.
		 */
		STRICT,
		/**
		 * Relaxed matching. DTLS session may have been resumed or UDP address
		 * may have changed.
		 */
		RELAXED,
		/**
		 * DTLS principal based matching. Requires unique principals.
		 */
		PRINCIPAL,
		/**
		 * DTLS principal based matching using the principal also as identity
		 * for {@link KeyMID}, {@link KeyToken} and {@link KeyUri}. Requires
		 * unique principals and incoming initiated traffic. Only using ping may
		 * enable a client to support this for later outgoing traffic.
		 * 
		 * @see CoapClient#ping()
		 * @see Request#newPing()
		 */
		PRINCIPAL_IDENTITY,
	}

	/**
	 * MID tracker mode.
	 */
	public enum TrackerMode {
		/**
		 * Disable tracker. May result in overload the other peer's MID
		 * deduplication mechanism.
		 */
		NULL,
		/**
		 * Keep track of used MID-groups. Good trade-off between
		 * resource-consumption and MID reuse.
		 */
		GROUPED,
		/**
		 * Keep track of used MIDs. High resource-consumption.
		 */
		MAPBASED
	}

	/**
	 * Congestion control mechanism.
	 *
	 * (Experimental.)
	 */
	public enum CongestionControlMode {
		/**
		 * Disable congestion control.
		 */
		NULL,
		/**
		 * Cocoa.
		 */
		COCOA,
		/**
		 * Cocoa using only RTOs of messages without retransmission.
		 */
		COCOA_STRONG,
		/**
		 * RTO based.
		 */
		BASIC_RTO,
		/**
		 * RTO linux algorithm.
		 */
		LINUX_RTO,
		/**
		 * RTO peak hopper.
		 */
		PEAKHOPPER_RTO
	}

	/**
	 * The default number of active peers to support.
	 */
	public static final int DEFAULT_MAX_ACTIVE_PEERS = 150000;

	/**
	 * The default timeout after which a peer is considered inactive (in
	 * seconds).
	 */
	public static final long DEFAULT_MAX_PEER_INACTIVITY_PERIOD_IN_SECONDS = 10 * 60;

	/**
	 * The default maximum resource body size that can be transparently
	 * transferred in a blockwise transfer.
	 */
	public static final int DEFAULT_MAX_RESOURCE_BODY_SIZE = 8192; // bytes

	/**
	 * The default maximum amount of time between transfers of individual blocks
	 * in a blockwise transfer before the blockwise transfer state is discarded
	 * (in seconds).
	 * <p>
	 * The default value of 5 minutes is chosen to be a little more than the
	 * default EXCHANGE_LIFETIME of 247s.
	 */
	public static final int DEFAULT_BLOCKWISE_STATUS_LIFETIME_IN_SECONDS = 5 * 60;

	/**
	 * The default interval for removing expired/stale blockwise entries (in
	 * seconds).
	 */
	public static final int DEFAULT_BLOCKWISE_STATUS_INTERVAL_IN_SECONDS = 5;

	/**
	 * The default mode used for error-responds for send blockwise payload.
	 * <p>
	 * The default value is {@code false}, which indicate that the server will
	 * not include the Block1 option in error responses.
	 * 
	 * @see <a href="https://github.com/eclipse/californium/issues/1937" target=
	 *      "_blank"> RFC7959 - Block1 Option in Error Response 4.08 (Request
	 *      Entity Incomplete)</a>
	 * 
	 * @since 3.4
	 */
	public static final boolean DEFAULT_BLOCKWISE_STRICT_BLOCK1_OPTION = false;

	/**
	 * The default mode used to respond for early blockwise negotiation, when
	 * response can be sent on one packet.
	 * <p>
	 * The default value is {@code false}, which indicate that the server will
	 * not include the Block2 option, if not required.
	 */
	public static final boolean DEFAULT_BLOCKWISE_STRICT_BLOCK2_OPTION = false;

	/**
	 * The default mode for fail-over on
	 * {@link ResponseCode#REQUEST_ENTITY_TOO_LARGE}.
	 */
	public static final boolean DEFAULT_BLOCKWISE_ENTITY_TOO_LARGE_AUTO_FAILOVER = true;

	/**
	 * The default value for {@link #PREFERRED_BLOCK_SIZE}
	 */
	public static final int DEFAULT_PREFERRED_BLOCK_SIZE = 512;

	/**
	 * The default value for {@link #MAX_MESSAGE_SIZE}
	 */
	public static final int DEFAULT_MAX_MESSAGE_SIZE = 1024;

	/**
	 * The default MID tracker.
	 * 
	 * Supported values are {@code NULL}, {@code GROUPED}, or {@code MAPBASED}.
	 */
	public static final TrackerMode DEFAULT_MID_TRACKER = TrackerMode.GROUPED;

	/**
	 * The default number of MID groups.
	 * <p>
	 * Used for {@link GroupedMessageIdTracker}.
	 */
	public static final int DEFAULT_MID_TRACKER_GROUPS = 16;

	/**
	 * The default exchange lifetime (in seconds).
	 */
	public static final long DEFAULT_EXCHANGE_LIFETIME_IN_SECONDS = 247;
	/**
	 * The default NON lifetime (in seconds).
	 * 
	 * @since 3.5
	 */
	public static final long DEFAULT_NON_LIFETIME_IN_SECONDS = 145;

	/**
	 * Mark and sweep deduplicator.
	 * 
	 * @see SweepDeduplicator
	 */
	public static final String DEDUPLICATOR_MARK_AND_SWEEP = "MARK_AND_SWEEP";
	/**
	 * Peers based deduplicator. Limits maximum messages kept per peer to
	 * {@link #PEERS_MARK_AND_SWEEP_MESSAGES}. Removes messages, even if
	 * exchange-lifetime is not expired.
	 * 
	 * @see SweepPerPeerDeduplicator
	 */
	public static final String DEDUPLICATOR_PEERS_MARK_AND_SWEEP = "PEERS_MARK_AND_SWEEP";
	/**
	 * Crop rotation deduplicator.
	 * 
	 * @see CropRotation
	 */
	public static final String DEDUPLICATOR_CROP_ROTATION = "CROP_ROTATION";

	/**
	 * No deduplicator.
	 * 
	 * @see NoDeduplicator
	 */
	public static final String NO_DEDUPLICATOR = "NO_DEDUPLICATOR";
	/**
	 * Default dedulicator.
	 */
	public static final String DEFAULT_DEDUPLICATOR = DEDUPLICATOR_MARK_AND_SWEEP;

	/**
	 * Default for messages per peers mark and sweep.
	 * 
	 * @see SweepPerPeerDeduplicator
	 */
	public static final int DEFAULT_PEERS_MARK_AND_SWEEP_MESSAGES = 64;

	/**
	 * Default interval for (peers) mark and sweep.
	 * 
	 * @see SweepDeduplicator
	 * @see SweepPerPeerDeduplicator
	 */
	public static final long DEFAULT_MARK_AND_SWEEP_INTERVAL_IN_SECONDS = 10;

	/**
	 * Default interval for crop rotation.
	 * 
	 * @see CropRotation
	 */
	public static final long DEFAULT_CROP_ROTATION_PERIOD_IN_SECONDS = DEFAULT_EXCHANGE_LIFETIME_IN_SECONDS;

	/**
	 * Default value for auto-replace in deduplictors.
	 */
	public static final boolean DEFAULT_DEDUPLICATOR_AUTO_REPLACE = true;

	/**
	 * The default response matcher.
	 * 
	 * Supported values are {@code STRICT}, {@code RELAXED}, or
	 * {@code PRINCIPAL}.
	 */
	public static final MatcherMode DEFAULT_RESPONSE_MATCHING = MatcherMode.STRICT;

	/**
	 * The default multicast mid range. Enable multicast, and MID reserve range
	 * of 65000..65335 for multicast. 0 to disable multicast.
	 */
	public static final int DEFAULT_MULTICAST_BASE_MID = 65000;

	/**
	 * The default token size.
	 */
	public static final int DEFAULT_TOKEN_SIZE_LIMIT = 8;
	/**
	 * The default number of maximum observes supported on the coap-server.
	 * 
	 * {@code 0} to disable the server side limitation of observers.
	 * 
	 * @since 3.6
	 */
	public static final int DEFAULT_MAX_SERVER_OBSERVES = 50000;

	/**
	 * The maximum number of active peers supported.
	 * <p>
	 * An active peer is a node with which we exchange CoAP messages. For each
	 * active peer we need to maintain some state, e.g. we need to keep track of
	 * MIDs and tokens in use with the peer. It therefore is reasonable to limit
	 * the number of peers so that memory consumption can be better predicted.
	 * <p>
	 * The default value of this property is {@link #DEFAULT_MAX_ACTIVE_PEERS}.
	 * <p>
	 * For clients this value can safely be set to a small one or two digit
	 * number as most clients will only communicate with a small set of peers
	 * (servers).
	 */
	public static final IntegerDefinition MAX_ACTIVE_PEERS = new IntegerDefinition(MODULE + "MAX_ACTIVE_PEERS",
			"Maximum number of active peers.", DEFAULT_MAX_ACTIVE_PEERS, 1);
	/**
	 * The maximum number of seconds a peer may be inactive for before it is
	 * considered stale and all state associated with it can be discarded.
	 */
	public static final TimeDefinition MAX_PEER_INACTIVITY_PERIOD = new TimeDefinition(
			MODULE + "MAX_PEER_INACTIVITY_PERIOD", "Maximum inactive period of peer.",
			DEFAULT_MAX_PEER_INACTIVITY_PERIOD_IN_SECONDS, TimeUnit.SECONDS);

	/**
	 * CoAP port.
	 */
	public static final IntegerDefinition COAP_PORT = new IntegerDefinition(MODULE + "COAP_PORT", "CoAP port.", 5683,
			1);
	/**
	 * CoAPs port.
	 */
	public static final IntegerDefinition COAP_SECURE_PORT = new IntegerDefinition(MODULE + "COAP_SECURE_PORT",
			"CoAP DTLS port.", 5684, 1);
	/**
	 * Initial CoAP acknowledge timeout for CON messages. See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-4.8"
	 * target="_blank">RFC7252 4.8. Transmission Parameters</a>.
	 */
	public static final TimeDefinition ACK_TIMEOUT = new TimeDefinition(MODULE + "ACK_TIMEOUT",
			"Initial CoAP acknowledge timeout.", 2000, TimeUnit.MILLISECONDS);
	/**
	 * Maximum CoAP acknowledge timeout for CON messages. Not RFC7252 compliant.
	 */
	public static final TimeDefinition MAX_ACK_TIMEOUT = new TimeDefinition(MODULE + "MAX_ACK_TIMEOUT",
			"Maximum CoAP acknowledge timeout.", 60000, TimeUnit.MILLISECONDS);
	/**
	 * Random factor applied to the initial CoAP acknowledge timeout. See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-4.8"
	 * target="_blank">RFC7252, 4.8. Transmission Parameters</a>.
	 */
	public static final FloatDefinition ACK_INIT_RANDOM = new FloatDefinition(MODULE + "ACK_INIT_RANDOM",
			"Random factor for initial CoAP acknowledge timeout.", 1.5F, 1.0F);
	/**
	 * Factor as back-off applied to follow-up CoAP acknowledge timeout. See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-4.2"
	 * target="_blank">RFC7252, 4.2. Messages Transmitted Reliably, "timeout is
	 * doubled"</a>.
	 */
	public static final FloatDefinition ACK_TIMEOUT_SCALE = new FloatDefinition(MODULE + "ACK_TIMEOUT_SCALE",
			"Scale factor for CoAP acknowledge backoff-timeout.", 2.0F, 1.0F);
	/**
	 * Maximum numbers of retransmissions. See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-4.8"
	 * target="_blank">RFC7252, 4.8. Transmission Parameters</a>.
	 */
	public static final IntegerDefinition MAX_RETRANSMIT = new IntegerDefinition(MODULE + "MAX_RETRANSMIT",
			"Maximum number of CoAP retransmissions.", 4, 1);
	/**
	 * The EXCHANGE_LIFETIME for CON requests. See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-4.8.2"
	 * target="_blank">RFC7252, 4.8.2. Time Values Derived from Transmission
	 * Parameters</a>.
	 */
	public static final TimeDefinition EXCHANGE_LIFETIME = new TimeDefinition(MODULE + "EXCHANGE_LIFETIME",
			"CoAP maximum exchange lifetime for CON requests.", DEFAULT_EXCHANGE_LIFETIME_IN_SECONDS, TimeUnit.SECONDS);
	/**
	 * The NON_LIFETIME for NON requests. See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-4.8.2"
	 * target="_blank">RFC7252, 4.8.2. Time Values Derived from Transmission
	 * Parameters</a>.
	 */
	public static final TimeDefinition NON_LIFETIME = new TimeDefinition(MODULE + "NON_LIFETIME",
			"CoAP maximum lifetime for NON requests.", DEFAULT_NON_LIFETIME_IN_SECONDS, TimeUnit.SECONDS);
	/**
	 * The maximum latency assumed for message transmission. See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-4.8.2"
	 * target="_blank">RFC7252, 4.8.2. Time Values Derived from Transmission
	 * Parameters</a>.
	 */
	public static final TimeDefinition MAX_LATENCY = new TimeDefinition(MODULE + "MAX_LATENCY",
			"Maximum transmission latency for messages.", 100, TimeUnit.SECONDS);
	/**
	 * The the maximum time from the first transmission of a Confirmable message
	 * to the time when the sender gives up on receiving an acknowledgement or
	 * reset. See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-4.8.2"
	 * target="_blank">RFC7252, 4.8.2. Time Values Derived from Transmission
	 * Parameters</a>.
	 */
	public static final TimeDefinition MAX_TRANSMIT_WAIT = new TimeDefinition(MODULE + "MAX_TRANSMIT_WAIT",
			"Maximum time to wait for ACK or RST after the first transmission of a CON message.", 93, TimeUnit.SECONDS);
	/**
	 * The maximum server response delay. See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7390#section-2.5"
	 * target="_blank">RFC7390, 2.5. Request and Response Model</a>.
	 */
	public static final TimeDefinition MAX_SERVER_RESPONSE_DELAY = new TimeDefinition(
			MODULE + "MAX_SERVER_RESPONSE_DELAY", "Maximum server response delay.", 250, TimeUnit.SECONDS);
	/**
	 * The number of concurrent maximum server response delay. See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-4.8"
	 * target="_blank">RFC7252, 4.8. Transmission Parameters</a>.
	 */
	public static final IntegerDefinition NSTART = new IntegerDefinition(MODULE + "NSTART",
			"Maximum concurrent transmissions.", 1, 1);
	/**
	 * The leisure of a multicast server for response delays. See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-4.8"
	 * target="_blank">RFC7252, 4.8. Transmission Parameters</a>.
	 */
	public static final TimeDefinition LEISURE = new TimeDefinition(MODULE + "LEISURE",
			"Timespan a multicast server may spread the response.", 5, TimeUnit.SECONDS);
	/**
	 * The probing rate for new destination endpoints. See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-4.8"
	 * target="_blank">RFC7252, 4.8. Transmission Parameters</a>. Currently not
	 * used.
	 */
	public static final FloatDefinition PROBING_RATE = new FloatDefinition(MODULE + "PROBING_RATE",
			"Probing rate to peers, which didn't response before. Currently not used.", 1.0F);
	/**
	 * Configure message-off-loading.
	 * 
	 * @see Message#offload(org.eclipse.californium.core.coap.Message.OffloadMode)
	 */
	public static final BooleanDefinition USE_MESSAGE_OFFLOADING = new BooleanDefinition(
			MODULE + "USE_MESSAGE_OFFLOADING", "Use message off-loading, when data is not longer required.", false);
	/**
	 * Use initially a random value for the MID.
	 * 
	 * Mitigates accidentally MID duplicates after restart with MIDs used before
	 * restart. Especially, if a blockwise transfer was ongoing before the
	 * restart, the random initial value may not help. In that cases, use a
	 * quiet period of {@link CoapConfig#EXCHANGE_LIFETIME}.
	 */
	public static final BooleanDefinition USE_RANDOM_MID_START = new BooleanDefinition(MODULE + "USE_RANDOM_MID_START",
			"Use initially a random value for MID.", true);

	/**
	 * MID tracker.
	 */
	public static final EnumDefinition<TrackerMode> MID_TRACKER = new EnumDefinition<>(MODULE + "MID_TACKER",
			"MID tracker.", TrackerMode.GROUPED, TrackerMode.values());
	/**
	 * Number of groups for {@link GroupedMessageIdTracker}.
	 */
	public static final IntegerDefinition MID_TRACKER_GROUPS = new IntegerDefinition(MODULE + "MID_TRACKER_GROUPS",
			"Number of MID tracker groups.", DEFAULT_MID_TRACKER_GROUPS, 4);
	/**
	 * Base MID for multicast MID range. All multicast requests use the same MID
	 * provider, which generates MIDs in the range [base...65536). None
	 * multicast request use the range [0...base). 0 := disable multicast
	 * support.
	 */
	public static final IntegerDefinition MULTICAST_BASE_MID = new IntegerDefinition(MODULE + "MULTICAST_BASE_MID",
			"Base MID for multicast requests.", DEFAULT_MULTICAST_BASE_MID, 0);
	/**
	 * Token size for {@link TokenGenerator}.
	 */
	public static final IntegerDefinition TOKEN_SIZE_LIMIT = new IntegerDefinition(MODULE + "TOKEN_SIZE_LIMIT",
			"Limit of token size.", DEFAULT_TOKEN_SIZE_LIMIT, 1);
	/**
	 * The block size (number of bytes) to use when doing a blockwise transfer.
	 * This value serves as the upper limit for block size in blockwise
	 * transfers.
	 */
	public static final IntegerDefinition PREFERRED_BLOCK_SIZE = new IntegerDefinition(MODULE + "PREFERRED_BLOCK_SIZE",
			"Preferred blocksize for blockwise transfer.", DEFAULT_PREFERRED_BLOCK_SIZE, 16);
	/**
	 * The maximum payload size (in bytes) that can be transferred in a single
	 * message, i.e. without requiring a blockwise transfer.
	 * 
	 * NB: this value MUST be adapted to the maximum message size supported by
	 * the transport layer. In particular, this value cannot exceed the
	 * network's MTU if UDP is used as the transport protocol.
	 */
	public static final IntegerDefinition MAX_MESSAGE_SIZE = new IntegerDefinition(MODULE + "MAX_MESSAGE_SIZE",
			"Maximum payload size.", DEFAULT_MAX_MESSAGE_SIZE, 16);
	/**
	 * The maximum size of a resource body (in bytes) that will be accepted as
	 * the payload of a POST/PUT or the response to a GET request in a
	 * <em>transparent</em> blockwise transfer.
	 * <p>
	 * This option serves as a safeguard against excessive memory consumption
	 * when many resources contain large bodies that cannot be transferred in a
	 * single CoAP message. This option has no impact on *manually* managed
	 * blockwise transfers in which the blocks are handled individually.
	 * <p>
	 * Note that this option does not prevent local clients or resource
	 * implementations from sending large bodies as part of a request or
	 * response to a peer.
	 * <p>
	 * The default value of this property is
	 * {@link #DEFAULT_MAX_RESOURCE_BODY_SIZE}.
	 * <p>
	 * A value of {@code 0} turns off transparent handling of blockwise
	 * transfers altogether.
	 */
	public static final IntegerDefinition MAX_RESOURCE_BODY_SIZE = new IntegerDefinition(
			MODULE + "MAX_RESOURCE_BODY_SIZE",
			"Maximum size of resource body. 0 to disable transparent blockwise mode.", DEFAULT_MAX_RESOURCE_BODY_SIZE,
			0);
	/**
	 * The maximum amount of time allowed between transfers of individual blocks
	 * in a blockwise transfer before the blockwise transfer state is discarded.
	 * <p>
	 * The default value of this property is
	 * {@link #DEFAULT_BLOCKWISE_STATUS_LIFETIME_IN_SECONDS}.
	 */
	public static final TimeDefinition BLOCKWISE_STATUS_LIFETIME = new TimeDefinition(
			MODULE + "BLOCKWISE_STATUS_LIFETIME", "Lifetime of blockwise status.",
			DEFAULT_BLOCKWISE_STATUS_LIFETIME_IN_SECONDS, TimeUnit.SECONDS);
	/**
	 * The interval for removing expired/stale blockwise entries.
	 * <p>
	 * The default value of this property is
	 * {@link #DEFAULT_BLOCKWISE_STATUS_INTERVAL_IN_SECONDS}.
	 */
	public static final TimeDefinition BLOCKWISE_STATUS_INTERVAL = new TimeDefinition(
			MODULE + "BLOCKWISE_STATUS_INTERVAL", "Interval to validate lifetime of blockwise status.",
			DEFAULT_BLOCKWISE_STATUS_INTERVAL_IN_SECONDS, TimeUnit.SECONDS);
	/**
	 * Number of BERT/TCP bulk blocks.
	 * 
	 * If the value is greater than 1, this sets up the active use of BERT. i.e.
	 * Messages will be sent with BERT option. The passive receiving of BERT
	 * message is always enabled while using TCP connector.
	 */
	public static final IntegerDefinition TCP_NUMBER_OF_BULK_BLOCKS = new IntegerDefinition(
			MODULE + "TCP_NUMBER_OF_BULK_BLOCKS", "Number of block per TCP-blockwise bulk transfer.", 1, 1);

	/**
	 * Property to indicate if the error-response should include the Block1
	 * option.
	 * <p>
	 * The default value of this property is
	 * {@link #DEFAULT_BLOCKWISE_STRICT_BLOCK1_OPTION}.
	 * </p>
	 * 
	 * @see <a href="https://github.com/eclipse/californium/issues/1937" target=
	 *      "_blank"> RFC7959 - Block1 Option in Error Response 4.08 (Request
	 *      Entity Incomplete)</a>
	 * 
	 * @since 3.4
	 */
	public static final BooleanDefinition BLOCKWISE_STRICT_BLOCK1_OPTION = new BooleanDefinition(
			MODULE + "BLOCKWISE_STRICT_BLOCK1_OPTION", "Use block1 option strictly, even for error-responses.",
			DEFAULT_BLOCKWISE_STRICT_BLOCK1_OPTION);

	/**
	 * Property to indicate if the response should always include the Block2
	 * option when client request early blockwise negotiation but the response
	 * can be sent on one packet.
	 * <p>
	 * The default value of this property is
	 * {@link #DEFAULT_BLOCKWISE_STRICT_BLOCK2_OPTION}.
	 * </p>
	 * 
	 * <ul>
	 * <li>A value of {@code false} indicate that the server will respond
	 * without block2 option if no further blocks are required.</li>
	 * <li>A value of {@code true} indicate that the server will response with
	 * block2 option event if no further blocks are required.</li>
	 * </ul>
	 * 
	 */
	public static final BooleanDefinition BLOCKWISE_STRICT_BLOCK2_OPTION = new BooleanDefinition(
			MODULE + "BLOCKWISE_STRICT_BLOCK2_OPTION", "Use block2 option strictly, even if block2 is not required.",
			DEFAULT_BLOCKWISE_STRICT_BLOCK2_OPTION);

	/**
	 * Property to automatically handle 4.13 Entity too large error with
	 * transparent blockwise transfer.
	 * <p>
	 * The default value is :
	 * {@link #DEFAULT_BLOCKWISE_ENTITY_TOO_LARGE_AUTO_FAILOVER }.
	 * <p>
	 * When activated ({@code true}), CoAP client will try to use block mode or
	 * adapt the block size when receiving a 4.13 Entity too large response
	 * code.
	 * <p>
	 * @see <a href="https://tools.ietf.org/html/rfc7959#section-2.9.3" target="_blank">RFC7959, 2.9.3. - 4.13 Request Entity Too Large</a>
	 */
	public static final BooleanDefinition BLOCKWISE_ENTITY_TOO_LARGE_AUTO_FAILOVER = new BooleanDefinition(
			MODULE + "BLOCKWISE_ENTITY_TOO_LARGE_AUTO_FAILOVER",
			"Enable automatic failover on \"entity too large\" response.",
			DEFAULT_BLOCKWISE_ENTITY_TOO_LARGE_AUTO_FAILOVER);
	/**
	 * Property to indicate that blockwise follow-up requests are reusing the
	 * same token for traceability.
	 * <p>
	 * <b>Note:</b> reusing tokens may introduce a vulnerability, if
	 * requests/response are captured and sent later without protecting the
	 * integrity of the payload by other means.
	 * </p>
	 * 
	 * @see <a href="https://github.com/core-wg/attacks-on-coap" target="_blank">attacks-on-coap</a>
	 * @since 3.8
	 */
	public static final BooleanDefinition BLOCKWISE_REUSE_TOKEN = new BooleanDefinition(
			MODULE + "BLOCKWISE_REUSE_TOKEN",
			"Reuse token for blockwise requests. Ease traceability but may introduce vulnerability.", false);

	/**
	 * Time interval for a coap-server to check the client's interest in further
	 * notifications.
	 * 
	 * Use a CON notification for that check.
	 * 
	 * @see ObserveRelation#check()
	 * @see CoapConfig#NOTIFICATION_CHECK_INTERVAL_COUNT
	 */
	public static final TimeDefinition NOTIFICATION_CHECK_INTERVAL_TIME = new TimeDefinition(
			MODULE + "NOTIFICATION_CHECK_INTERVAL",
			"Interval time to check notifications receiver using a CON message.", 120L, TimeUnit.SECONDS);
	/**
	 * Number of notifications for a coap-server to check the client's interest
	 * in further notifications.
	 * 
	 * Use a CON notification for that check.
	 * 
	 * @see ObserveRelation#check()
	 * @see CoapConfig#NOTIFICATION_CHECK_INTERVAL_TIME
	 */
	public static final IntegerDefinition NOTIFICATION_CHECK_INTERVAL_COUNT = new IntegerDefinition(
			MODULE + "NOTIFICATION_CHECK_INTERVAL_COUNT",
			"Interval counter to check notifications receiver using a CON message.", 100);
	/**
	 * Backoff time for a coap-client to reregister stale observations.
	 * 
	 * The coap-server is intended to set the max-age in the response/notify
	 * according
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7641#section-4.3.1"
	 * target="_blank"> RFC764, 4.3.1. Freshness</a>. If additionally to that
	 * max-age this backoff time expires without a new notification, the
	 * coap-client reregisters in order to ensure, that the coap-server has
	 * still registered the interest.
	 */
	public static final TimeDefinition NOTIFICATION_REREGISTRATION_BACKOFF = new TimeDefinition(
			MODULE + "NOTIFICATION_REREGISTRATION_BACKOFF",
			"Additional time (backoff) to the max-age option\nfor waiting for the next notification before reregister.",
			2000L, TimeUnit.MILLISECONDS);
	/**
	 * The maximum number of observes supported on the coap-server.
	 * 
	 * {@code 0} to disable the server side limitation of observers.
	 * 
	 * @since 3.6
	 */
	public static final IntegerDefinition MAX_SERVER_OBSERVES = new IntegerDefinition(MODULE + "MAX_SERVER_OBSERVES",
			"Maximum number of observes on server-side. 0 to disable this limitation.", DEFAULT_MAX_SERVER_OBSERVES);

	/**
	 * Congestion control algorithm. Still experimental.
	 */
	public static final EnumDefinition<CongestionControlMode> CONGESTION_CONTROL_ALGORITHM = new EnumDefinition<>(
			MODULE + "CONGESTION_CONTROL_ALGORITHM", "Congestion-Control algorithm (still experimental).",
			CongestionControlMode.NULL, CongestionControlMode.values());

	/**
	 * Force congestion control algorithm to use inet-address instead of remote
	 * peer's identity.
	 * 
	 * The {@link EndpointIdentityResolver} enables Californium to use a
	 * different remote identity instead of the inet-address to process states.
	 * For congestion control that may result in less good results, if an
	 * inet-address change, maybe caused by a NAT, also changes the quality of
	 * the ip-route. In such cases, it may be better to switch to inet-address
	 * based congestion control.
	 * 
	 * @since 3.8
	 */
	public static final BooleanDefinition CONGESTION_CONTROL_USE_INET_ADDRESS = new BooleanDefinition(
			MODULE + "CONGESTION_CONTROL_USE_INET_ADDRESS",
			"Use inet-address for congestion control, even if an other peer identity is used."
					+ " Enable, if NAT changes are also changing the quality of the ip-route.",
			false);

	/**
	 * Number of threads to process coap-exchanges.
	 */
	public static final IntegerDefinition PROTOCOL_STAGE_THREAD_COUNT = new IntegerDefinition(
			MODULE + "PROTOCOL_STAGE_THREAD_COUNT", "Protocol stage thread count.", 1, 0);

	/**
	 * Deduplicator algorithm.
	 * 
	 * @see NoDeduplicator
	 * @see CropRotation
	 * @see SweepDeduplicator
	 * @see SweepPerPeerDeduplicator
	 */
	public static final StringSetDefinition DEDUPLICATOR = new StringSetDefinition(MODULE + "DEDUPLICATOR",
			"Deduplicator algorithm.", DEDUPLICATOR_MARK_AND_SWEEP, DEDUPLICATOR_MARK_AND_SWEEP,
			DEDUPLICATOR_PEERS_MARK_AND_SWEEP, DEDUPLICATOR_CROP_ROTATION, NO_DEDUPLICATOR);
	/**
	 * The interval after which the next sweep run should occur.
	 */
	public static final TimeDefinition MARK_AND_SWEEP_INTERVAL = new TimeDefinition(MODULE + "MARK_AND_SWEEP_INTERVAL",
			"Mark and sweep interval.", DEFAULT_MARK_AND_SWEEP_INTERVAL_IN_SECONDS, TimeUnit.SECONDS);
	/**
	 * The number of messages per peer kept for deduplication.
	 * 
	 * @see SweepPerPeerDeduplicator
	 */
	public static final IntegerDefinition PEERS_MARK_AND_SWEEP_MESSAGES = new IntegerDefinition(
			MODULE + "PEERS_MARK_AND_SWEEP_MESSAGES",
			"Maximum messages kept per peer for " + DEDUPLICATOR_PEERS_MARK_AND_SWEEP + ".",
			DEFAULT_PEERS_MARK_AND_SWEEP_MESSAGES, 4);
	/**
	 * The interval after which the next crop run should occur.
	 * 
	 * @see CropRotation
	 */
	public static final TimeDefinition CROP_ROTATION_PERIOD = new TimeDefinition(MODULE + "CROP_ROTATION_PERIOD",
			"Crop rotation period.", DEFAULT_CROP_ROTATION_PERIOD_IN_SECONDS, TimeUnit.SECONDS);
	/**
	 * Enable auto replace of not matching exchanges.
	 * 
	 * Sometimes, mainly triggered by not-aware address changes, wrong messages
	 * hit the deduplictor. Especially it the direction of the exchanges is
	 * changing, that's mainly caused by such address changes and a automatic
	 * replacement overcomes that.
	 */
	public static final BooleanDefinition DEDUPLICATOR_AUTO_REPLACE = new BooleanDefinition(
			MODULE + "DEDUPLICATOR_AUTO_REPLACE", "Automatic replace entries in deduplicator.", true);
	/**
	 * Response matching.
	 */
	public static final EnumDefinition<MatcherMode> RESPONSE_MATCHING = new EnumDefinition<>(
			MODULE + "RESPONSE_MATCHING", "Response matching mode.", MatcherMode.STRICT, MatcherMode.values());

	/**
	 * Disable/enable strict empty message format processing.
	 * 
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-4.1"
	 * target="_blank">RFC7252, Section 4.1</a> defines:
	 * 
	 * <pre>
	 * An Empty message has the Code field set to 0.00.  The Token Length
	 * field MUST be set to 0 and bytes of data MUST NOT be present after
	 * the Message ID field.  If there are any bytes, they MUST be processed
	 * as a message format error.
	 * </pre>
	 * 
	 * The behavior before 3.5 was ignoring such tokens, options or payload.
	 * 
	 * @since 3.5
	 */
	public static final BooleanDefinition STRICT_EMPTY_MESSAGE_FORMAT = new BooleanDefinition(
			MODULE + "STRICT_EMPTY_MESSAGE_FORMAT",
			"Process empty messages strictly according RFC7252, 4.1 as format error. Disable to ignore additional data as tokens or options.",
			true);

	public static final ModuleDefinitionsProvider DEFINITIONS = new ModuleDefinitionsProvider() {

		@Override
		public String getModule() {
			return MODULE;
		}

		@Override
		public void applyDefinitions(Configuration config) {
			final int CORES = Runtime.getRuntime().availableProcessors();

			config.set(MAX_ACTIVE_PEERS, DEFAULT_MAX_ACTIVE_PEERS);
			config.set(MAX_PEER_INACTIVITY_PERIOD, DEFAULT_MAX_PEER_INACTIVITY_PERIOD_IN_SECONDS, TimeUnit.SECONDS);

			config.set(COAP_PORT, CoAP.DEFAULT_COAP_PORT);
			config.set(COAP_SECURE_PORT, CoAP.DEFAULT_COAP_SECURE_PORT);

			config.set(ACK_TIMEOUT, 2000, TimeUnit.MILLISECONDS);
			config.set(MAX_ACK_TIMEOUT, 60000, TimeUnit.MILLISECONDS);
			config.set(ACK_INIT_RANDOM, 1.5f);
			config.set(ACK_TIMEOUT_SCALE, 2f);
			config.set(MAX_RETRANSMIT, 4);
			config.set(EXCHANGE_LIFETIME, DEFAULT_EXCHANGE_LIFETIME_IN_SECONDS, TimeUnit.SECONDS);
			config.set(NON_LIFETIME, 145, TimeUnit.SECONDS);
			config.set(NSTART, 1);
			config.set(LEISURE, 5, TimeUnit.SECONDS);
			config.set(PROBING_RATE, 1f);
			config.set(USE_MESSAGE_OFFLOADING, false);

			config.set(MAX_LATENCY, 100, TimeUnit.SECONDS);
			config.set(MAX_TRANSMIT_WAIT, 93, TimeUnit.SECONDS);
			config.set(MAX_SERVER_RESPONSE_DELAY, 250, TimeUnit.SECONDS);

			config.set(USE_RANDOM_MID_START, true);
			config.set(MID_TRACKER, DEFAULT_MID_TRACKER);
			config.set(MID_TRACKER_GROUPS, DEFAULT_MID_TRACKER_GROUPS);
			config.set(TOKEN_SIZE_LIMIT, 8);

			config.set(PREFERRED_BLOCK_SIZE, DEFAULT_PREFERRED_BLOCK_SIZE);
			config.set(MAX_MESSAGE_SIZE, DEFAULT_MAX_MESSAGE_SIZE);
			config.set(MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_BODY_SIZE);
			config.set(BLOCKWISE_STATUS_LIFETIME, DEFAULT_BLOCKWISE_STATUS_LIFETIME_IN_SECONDS, TimeUnit.SECONDS);
			config.set(BLOCKWISE_STATUS_INTERVAL, DEFAULT_BLOCKWISE_STATUS_INTERVAL_IN_SECONDS, TimeUnit.SECONDS);
			config.set(BLOCKWISE_STRICT_BLOCK1_OPTION, DEFAULT_BLOCKWISE_STRICT_BLOCK1_OPTION);
			config.set(BLOCKWISE_STRICT_BLOCK2_OPTION, DEFAULT_BLOCKWISE_STRICT_BLOCK2_OPTION);
			config.set(BLOCKWISE_ENTITY_TOO_LARGE_AUTO_FAILOVER, DEFAULT_BLOCKWISE_ENTITY_TOO_LARGE_AUTO_FAILOVER);
			config.set(BLOCKWISE_REUSE_TOKEN, false);
			// BERT enabled, when > 1
			config.set(TCP_NUMBER_OF_BULK_BLOCKS, 4);

			config.set(NOTIFICATION_CHECK_INTERVAL_TIME, 120, TimeUnit.SECONDS);
			config.set(NOTIFICATION_CHECK_INTERVAL_COUNT, 100);
			config.set(NOTIFICATION_REREGISTRATION_BACKOFF, 2000, TimeUnit.MILLISECONDS);

			config.set(CONGESTION_CONTROL_ALGORITHM, CongestionControlMode.NULL);
			config.set(CONGESTION_CONTROL_USE_INET_ADDRESS, false);
			config.set(PROTOCOL_STAGE_THREAD_COUNT, CORES);

			config.set(DEDUPLICATOR, DEFAULT_DEDUPLICATOR);
			config.set(MARK_AND_SWEEP_INTERVAL, DEFAULT_MARK_AND_SWEEP_INTERVAL_IN_SECONDS, TimeUnit.SECONDS);
			config.set(PEERS_MARK_AND_SWEEP_MESSAGES, DEFAULT_PEERS_MARK_AND_SWEEP_MESSAGES);
			config.set(CROP_ROTATION_PERIOD, DEFAULT_CROP_ROTATION_PERIOD_IN_SECONDS, TimeUnit.SECONDS);
			config.set(DEDUPLICATOR_AUTO_REPLACE, DEFAULT_DEDUPLICATOR_AUTO_REPLACE);
			config.set(RESPONSE_MATCHING, DEFAULT_RESPONSE_MATCHING);

			config.set(MULTICAST_BASE_MID, DEFAULT_MULTICAST_BASE_MID);
			config.set(STRICT_EMPTY_MESSAGE_FORMAT, true);

			config.set(MAX_SERVER_OBSERVES, DEFAULT_MAX_SERVER_OBSERVES);
			DefinitionUtils.verify(CoapConfig.class, config);
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
