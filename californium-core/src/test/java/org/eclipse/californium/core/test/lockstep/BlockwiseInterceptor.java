/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add CANCELED to log
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;

/**
 * A base class for implementing message interceptors.
 *
 */
public abstract class BlockwiseInterceptor {

	protected StringBuilder buffer = new StringBuilder();

	protected BlockwiseInterceptor() {
		// do nothing
	}

	/**
	 * Adds a message to the buffer.
	 * 
	 * @param str The message to add.
	 */
	public final synchronized void log(final String str) {
		buffer.append(str);
	}

	protected final void appendBlockOption(final int nbr, final BlockOption option) {
		if (option != null) {
			buffer.append(", ").append(nbr).append(":")
				.append(option.getNum()).append("/").append(option.isM() ? 1 : 0).append("/").append(option.getSize());
		}
	}

	protected final void appendObserveOption(final OptionSet options) {
		if (options != null && options.hasObserve()) {
			buffer.append(", observe(").append(options.getObserve()).append(")");
		}
	}

	protected final void appendSize1(final OptionSet options) {
		if (options != null && options.hasSize1()) {
			buffer.append(", size1(").append(options.getSize1()).append(")");
		}
	}

	protected final void appendSize2(final OptionSet options) {
		if (options != null && options.hasSize2()) {
			buffer.append(", size2(").append(options.getSize2()).append(")");
		}
	}

	protected final void appendEtags(final OptionSet options) {
		if (options != null && options.getETagCount() > 0) {
			buffer.append(", ETags(");
			int i = 0;
			for (byte[] tag : options.getETags()) {
				buffer.append(Utils.toHexString(tag));
				if (++i < options.getETagCount()) {
					buffer.append(", ");
				}
			}
			buffer.append(")");
		}
	}
	protected final void appendRequestDetails(final Request request) {
		if (request.isCanceled()) {
			buffer.append("CANCELED ");
		}
		buffer.append(request.getType()).append(" [MID=").append(request.getMID())
			.append(", T=").append(request.getTokenString()).append("], ")
			.append(request.getCode()).append(", /").append(request.getOptions().getUriPathString());
		appendBlockOption(1, request.getOptions().getBlock1());
		appendBlockOption(2, request.getOptions().getBlock2());
		appendObserveOption(request.getOptions());
		appendSize1(request.getOptions());
		appendEtags(request.getOptions());
	}

	protected final void appendResponseDetails(final Response response) {
		if (response.isCanceled()) {
			buffer.append("CANCELED ");
		}
		buffer.append(response.getType()).append(" [MID=").append(response.getMID())
			.append(", T=").append(response.getTokenString()).append("], ")
			.append(response.getCode());
		appendBlockOption(1, response.getOptions().getBlock1());
		appendBlockOption(2, response.getOptions().getBlock2());
		appendObserveOption(response.getOptions());
		appendSize1(response.getOptions());
		appendSize2(response.getOptions());
		appendEtags(response.getOptions());
	}

	protected final void appendEmptyMessageDetails(final EmptyMessage message) {
		if (message.isCanceled()) {
			buffer.append("CANCELED ");
		}
		buffer.append(message.getType()).append(" [MID=").append(message.getMID()).append("]");
	}

	@Override
	public final String toString() {
		return buffer.append(System.lineSeparator()).substring(1);
	}

	/**
	 * Clears the buffer.
	 */
	public final void clear() {
		buffer = new StringBuilder();
	}

}
