/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.option;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.option.IntegerOption;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DatagramReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CoAP custom time option.
 * <p>
 * Used in {@link Request} to indicate the client's system-time in milliseconds.
 * If the used value is {@code 0} or differs from the system-time of the server
 * more than {@link #MAX_MILLISECONDS_DELTA}, the server adds also a
 * {@link TimeOption} to the {@link Response} with the server's system-time in
 * milliseconds.
 * 
 * @since 3.12
 */
public class TimeOption extends IntegerOption {

	/**
	 * Logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(TimeOption.class);

	/**
	 * Number of custom option.
	 */
	public static final int COAP_OPTION_TIME = 0xfde8;

	/**
	 * Maximum delta in milliseconds.
	 * <p>
	 * If exceeded, {@link #adjust()} returns the {@link TimeOption} to be added
	 * to the {@link Response}.
	 */
	public static final long MAX_MILLISECONDS_DELTA = 5000;

	public static final Definition DEFINITION = new Definition(COAP_OPTION_TIME, "Time");

	/**
	 * Adjust value, if times differ more than {@link #MAX_MILLISECONDS_DELTA}.
	 * 
	 * @see #adjust()
	 */
	private boolean adjustTime;

	@Override
	public Definition getDefinition() {
		return (Definition) super.getDefinition();
	}

	@Override
	public String toValueString() {
		long time = getLongValue();
		if (time > 0) {
			return new Date(time).toString();
		}
		return "0";
	}

	/**
	 * Get time option to adjust the device time.
	 * <p>
	 * Intended to be included in the response message, if indicated.
	 * 
	 * @return time option to adjust the device time, {@code null}, if the
	 *         device time is already set.
	 */
	public TimeOption adjust() {
		if (adjustTime) {
			Definition definition = getDefinition();
			return definition.create();
		}
		return null;
	}

	/**
	 * Get time option from message or clock.
	 * <p>
	 * If message contains custom time option, return that. Otherwise use the
	 * system receive time to create a time option to return.
	 * 
	 * @param message message with custom time option
	 * @return the time option
	 * @throws NullPointerException if message is {@code null}
	 */
	public static TimeOption getMessageTime(Message message) {
		if (message == null) {
			throw new NullPointerException("Message must not be null!");
		}
		long delta = ClockUtil.delta(message.getNanoTimestamp(), TimeUnit.MILLISECONDS);
		long receiveTime = System.currentTimeMillis() - delta;
		Definition definition = null;
		TimeOption option = message.getOptions().getOtherOption(DEFINITION);
		if (option != null) {
			definition = DEFINITION;
		} else {
			option = message.getOptions().getOtherOption(DEPRECATED_DEFINITION);
			if (option != null) {
				definition = DEPRECATED_DEFINITION;
			}
		}
		if (option != null) {
			long value = option.getLongValue();
			if (value == 0) {
				option = definition.create(receiveTime);
				option.adjustTime = true;
				LOGGER.info("Time: send initial time");
			} else {
				delta = value - receiveTime;
				if (Math.abs(delta) > MAX_MILLISECONDS_DELTA) {
					// difference > 5s => send time fix back.
					option.adjustTime = true;
					LOGGER.info("Time: {}ms delta => send fix", delta);
				} else {
					LOGGER.debug("Time: {}ms delta", delta);
				}
			}
			return option;
		} else {
			LOGGER.debug("Time: localtime");
			return DEFINITION.create(receiveTime);
		}
	}

	/**
	 * Number of custom option.
	 */
	private static final int DEPRECATED_COAP_OPTION_TIME = 0xff3c;

	public static final Definition DEPRECATED_DEFINITION = new Definition(DEPRECATED_COAP_OPTION_TIME, "_Time");

	public TimeOption(Definition definition) {
		super(definition, System.currentTimeMillis());
	}

	public TimeOption(Definition definition, long value) {
		super(definition, value);
	}

	public static class Definition extends IntegerOption.Definition {

		private Definition(int number, String name) {
			super(number, name, true);
		}

		@Override
		public TimeOption create(DatagramReader reader, int length) {
			if (reader == null) {
				throw new NullPointerException("Option " + getName() + " reader must not be null.");
			}
			return new TimeOption(this, getLongValue(reader, length));
		}

		@Override
		public TimeOption create(long value) {
			return new TimeOption(this, value);
		}

		public TimeOption create() {
			return new TimeOption(this);
		}
	}

}
