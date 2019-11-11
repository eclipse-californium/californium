/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add CANCELED to log
 *    Achim Kraus (Bosch Software Innovations GmbH) - add time to log
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.test.ErrorInjector;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.util.IntendedTestException;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * A base class for implementing message interceptors.
 *
 */
public abstract class BlockwiseInterceptor {

	private final long startNano = System.nanoTime();

	protected ErrorInjector errorInjector;

	protected final StringBuilder buffer = new StringBuilder();

	protected BlockwiseInterceptor() {
		// do nothing
	}

	public final synchronized void setErrorInjector(ErrorInjector errorInjector) {
		this.errorInjector = errorInjector;
	}

	/**
	 * Adds a new line with timestamp to the buffer.
	 */
	public final synchronized void logNewLine() {
		buffer.append(StringUtil.lineSeparator());
		final long deltaMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNano);
		buffer.append(String.format("%04d: ", deltaMillis));
	}

	/**
	 * Adds a new line with timestamp and provided message to the buffer.
	 * 
	 * @param str The message to add.
	 */
	public final synchronized void logNewLine(final String str) {
		logNewLine();
		buffer.append(str);
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
			buffer.append(", ").append(nbr).append(":").append(option.getNum()).append("/").append(option.isM() ? 1 : 0)
					.append("/").append(option.getSize());
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
		buffer.append(request.getType()).append(" [MID=").append(request.getMID()).append(", T=")
				.append(request.getTokenString()).append("], ").append(request.getCode()).append(", /")
				.append(request.getOptions().getUriPathString());
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
		buffer.append(response.getType()).append(" [MID=").append(response.getMID()).append(", T=")
				.append(response.getTokenString()).append("], ").append(response.getCode());
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
		return buffer.toString();
	}

	/**
	 * Clears the buffer.
	 */
	public synchronized final void clear() {
		buffer.setLength(0);
		errorInjector = null;
	}

	protected static abstract class LoggingMessageObserver extends MessageObserverAdapter {

		private final MessageObserver errorInjectorObserver;

		protected LoggingMessageObserver(final ErrorInjector errorInjector) {
			this.errorInjectorObserver = errorInjector.new ErrorInjectorMessageObserver();
		}

		@Override
		public void onReadyToSend() {
			try {
				errorInjectorObserver.onReadyToSend();
			} catch (IntendedTestException exception) {
				log(exception);
				throw exception;
			}
		}

		@Override
		public void onSent(boolean retransmission) {
			try {
				errorInjectorObserver.onSent(retransmission);
				log(null);
			} catch (IntendedTestException exception) {
				log(exception);
				throw exception;
			}
		}

		@Override
		public void onContextEstablished(EndpointContext endpointContext) {
			try {
				errorInjectorObserver.onContextEstablished(endpointContext);
			} catch (IntendedTestException exception) {
				log(exception);
				throw exception;
			}
		}

		public abstract void log(IntendedTestException exception);
	}

	protected abstract class SendMessageObserver extends MessageObserverAdapter {

		private final AtomicBoolean log = new AtomicBoolean();

		@Override
		public void failed() {
			if (log.compareAndSet(false, true)) {
				log("(drop)");
			}
		}

		@Override
		public void onSent(boolean retransmission) {
			if (log.compareAndSet(false, true)) {
				log(null);
			}
			super.onSent(retransmission);
		}

		public abstract void log(String qualifier);
	}
}
