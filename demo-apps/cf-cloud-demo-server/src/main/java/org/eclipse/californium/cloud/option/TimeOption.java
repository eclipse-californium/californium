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

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.option.IntegerOptionDefinition;
import org.eclipse.californium.elements.util.ClockUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CoAP custom time option.
 * 
 * Used in {@link Request} to indicate the client's system-time in milliseconds.
 * If the used value is {@code 0} or differs from the system-time of the server
 * more than {@link #MAX_MILLISECONDS_DELTA}, the server adds also a
 * {@link TimeOption} to the {@link Response} with the server's system-time in
 * milliseconds.
 * 
 * @since 3.12
 */
public class TimeOption extends Option {

	/**
	 * Logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(TimeOption.class);

	/**
	 * Number of custom option.
	 */
	public static final int COAP_OPTION_TIME = 0xfde8;

	/**
	 * Maximum delta in milliseconds. If exceeded, {@link #adjust()} returns the
	 * {@link TimeOption} to be added to the {@link Response}.
	 */
	public static final long MAX_MILLISECONDS_DELTA = 5000;

	public static final IntegerOptionDefinition DEFINITION = new IntegerOptionDefinition(COAP_OPTION_TIME, "Time",
			true) {

		@Override
		public Option create(byte[] value) {
			return new TimeOption(value);
		}

	};

	/**
	 * Adjust value, if times differ more than {@link #MAX_MILLISECONDS_DELTA}.
	 * 
	 * @see #adjust()
	 */
	private boolean adjustTime;

	/**
	 * Create time option with current system time.
	 */
	public TimeOption() {
		this(System.currentTimeMillis());
	}

	/**
	 * Create time option.
	 * 
	 * @param time time in system milliseconds.
	 */
	public TimeOption(long time) {
		super(DEFINITION, time);
	}

	/**
	 * Create time option.
	 * 
	 * @param value time in system milliseconds as byte array.
	 */
	public TimeOption(byte[] value) {
		super(DEFINITION, value);
	}

	/**
	 * Get time option to adjust the device time.
	 * 
	 * Intended to be included in the response message, if indicated.
	 * 
	 * @return time option to adjust the device time, {@code null}, if the
	 *         device time is already set.
	 */
	public TimeOption adjust() {
		return adjustTime ? new TimeOption((IntegerOptionDefinition) getDefinition()) : null;
	}

	/**
	 * Get time option from message or clock.
	 * 
	 * If message contains custom time option, return that. Otherwise use the
	 * system receive time to create a time option to return.
	 * 
	 * @param message message with custom time option
	 * @return the time option
	 */
	public static TimeOption getMessageTime(Message message) {
		long delta = ClockUtil.delta(message.getNanoTimestamp(), TimeUnit.MILLISECONDS);
		long receiveTime = System.currentTimeMillis() - delta;
		Option option = message.getOptions().getOtherOption(DEFINITION);
		if (option == null) {
			option = message.getOptions().getOtherOption(DEPRECATED_DEFINITION);
		}
		if (option != null) {
			TimeOption time;
			IntegerOptionDefinition definition = (IntegerOptionDefinition) option.getDefinition();
			long value = option.getLongValue();
			if (value == 0) {
				time = new TimeOption(definition, receiveTime);
				time.adjustTime = true;
				LOGGER.info("Time: send initial time");
			} else {
				time = (TimeOption) option;
				delta = value - receiveTime;
				if (Math.abs(delta) > MAX_MILLISECONDS_DELTA) {
					// difference > 5s => send time fix back.
					time.adjustTime = true;
					LOGGER.info("Time: {}ms delta => send fix", delta);
				} else {
					LOGGER.debug("Time: {}ms delta", delta);
				}
			}
			return time;
		} else {
			LOGGER.debug("Time: localtime");
			return new TimeOption(receiveTime);
		}
	}

	/**
	 * Number of custom option.
	 */
	private static final int DEPRECATED_COAP_OPTION_TIME = 0xff3c;

	public static final IntegerOptionDefinition DEPRECATED_DEFINITION = new IntegerOptionDefinition(
			DEPRECATED_COAP_OPTION_TIME, "_Time", true) {

		@Override
		public Option create(byte[] value) {
			return new TimeOption(DEPRECATED_DEFINITION, value);
		}

	};

	private TimeOption(IntegerOptionDefinition definition) {
		super(definition, System.currentTimeMillis());
	}

	private TimeOption(IntegerOptionDefinition definition, long value) {
		super(definition, value);
	}

	private TimeOption(IntegerOptionDefinition definition, byte[] value) {
		super(definition, value);
	}
}
