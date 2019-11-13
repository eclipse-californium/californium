/*******************************************************************************
 * Copyright (c) 2019 Lari Hotari and others.
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
 *     Lari Hotari - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.network.config.NetworkConfig;

/**
 * Contains the configuration values for {@link ReliabilityLayer} and {@link CongestionControlLayer}
 */
public class ReliabilityLayerParameters {
	private final int ackTimeout;
	private final float ackRandomFactor;
	private final float ackTimeoutScale;
	private final int maxRetransmit;
	private final int nstart;

	ReliabilityLayerParameters(int ackTimeout, float ackRandomFactor, float ackTimeoutScale, int maxRetransmit, int nstart) {
		this.ackTimeout = ackTimeout;
		this.ackRandomFactor = ackRandomFactor;
		this.ackTimeoutScale = ackTimeoutScale;
		this.maxRetransmit = maxRetransmit;
		this.nstart = nstart;
	}

	public int getAckTimeout() {
		return ackTimeout;
	}

	public float getAckRandomFactor() {
		return ackRandomFactor;
	}

	public float getAckTimeoutScale() {
		return ackTimeoutScale;
	}

	public int getMaxRetransmit() {
		return maxRetransmit;
	}

	public int getNstart() {
		return nstart;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static final class Builder {
		private int ackTimeout;
		private float ackRandomFactor;
		private float ackTimeoutScale;
		private int maxRetransmit;
		private int nstart;

		private Builder() {
		}

		public Builder applyConfig(NetworkConfig config) {
			ackTimeout = config.getInt(NetworkConfig.Keys.ACK_TIMEOUT);
			ackRandomFactor = config.getFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR);
			ackTimeoutScale = config.getFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE);
			maxRetransmit = config.getInt(NetworkConfig.Keys.MAX_RETRANSMIT);
			nstart = config.getInt(NetworkConfig.Keys.NSTART);
			return this;
		}

		public Builder ackTimeout(int ackTimeout) {
			this.ackTimeout = ackTimeout;
			return this;
		}

		public Builder ackRandomFactor(float ackRandomFactor) {
			this.ackRandomFactor = ackRandomFactor;
			return this;
		}

		public Builder ackTimeoutScale(float ackTimeoutScale) {
			this.ackTimeoutScale = ackTimeoutScale;
			return this;
		}

		public Builder maxRetransmit(int maxRetransmit) {
			this.maxRetransmit = maxRetransmit;
			return this;
		}

		public Builder nstart(int nstart) {
			this.nstart = nstart;
			return this;
		}

		public ReliabilityLayerParameters build() {
			return new ReliabilityLayerParameters(ackTimeout, ackRandomFactor, ackTimeoutScale, maxRetransmit, nstart);
		}
	}
}
