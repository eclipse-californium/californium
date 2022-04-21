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
 *    Bosch IO.GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.config;

import java.util.concurrent.TimeUnit;

/**
 * Time definition.
 * 
 * Access always with {@link TimeUnit}.
 * 
 * @see Configuration#set(TimeDefinition, int, TimeUnit)
 * @see Configuration#set(TimeDefinition, Long, TimeUnit)
 * @see Configuration#get(TimeDefinition, TimeUnit)
 * @see Configuration#getTimeAsInt(TimeDefinition, TimeUnit)
 * @since 3.0
 */
public class TimeDefinition extends DocumentedDefinition<Long> {

	/**
	 * Creates time definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @throws NullPointerException if key is {@code null}
	 */
	public TimeDefinition(String key, String documentation) {
		super(key, documentation, Long.class, null);
	}

	/**
	 * Creates time definition with default value.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @param unit time unit of value
	 * @throws NullPointerException if key or unit is {@code null}
	 */
	public TimeDefinition(String key, String documentation, long defaultValue, TimeUnit unit) {
		super(key, documentation, Long.class, TimeUnit.NANOSECONDS.convert(defaultValue, unit));
	}

	@Override
	public String getTypeName() {
		return "Time";
	}

	@Override
	public String writeValue(Long value) {
		TimeUnit unit = TimeUnit.MILLISECONDS;
		if (value != 0) {
			unit = TimeUnit.NANOSECONDS;
			if (value % 1000L == 0) {
				unit = TimeUnit.MICROSECONDS;
				value /= 1000L;
				if (value % 1000L == 0) {
					unit = TimeUnit.MILLISECONDS;
					value /= 1000L;
					if (value % 1000L == 0) {
						unit = TimeUnit.SECONDS;
						value /= 1000L;
						if (value % 60L == 0) {
							unit = TimeUnit.MINUTES;
							value /= 60L;
							if (value % 60L == 0) {
								unit = TimeUnit.HOURS;
								value /= 60L;
								if (value % 24L == 0) {
									unit = TimeUnit.DAYS;
									value /= 24L;
								}
							}
						}
					}
				}
			}
		}
		return value + "[" + getTimeUnitAsText(unit) + "]";
	}

	@Override
	public Long checkValue(Long value) throws ValueException {
		if (value != null && value < 0) {
			throw new ValueException("Time " + value + " must be not less than 0!");
		}
		return value;
	}

	@Override
	protected Long parseValue(String value) throws ValueException {
		return parse(value);
	}

	/**
	 * Parse textual time value.
	 * 
	 * @param value textual time value. e.g. {@code "100[s]"}. Supported time
	 *            units: {@code "ns"} (nanoseconds), {@code "ys"}
	 *            (microseconds), {@code "ms"} (milliseconds), {@code "s"}
	 *            (seconds), {@code "min"} (minutes),{@code "h"} (hours), and
	 *            {@code "d"} (days).
	 * @return time value in {@link TimeUnit#NANOSECONDS}.
	 * @throws ValueException if value is no valid time value.
	 * @since 3.5
	 */
	public static Long parse(String value) throws ValueException {
		TimeUnit valueUnit = TimeUnit.MILLISECONDS;
		String num = value;
		int pos = value.indexOf('[');
		if (pos >= 0) {
			int end = value.indexOf(']');
			if (pos < end) {
				num = value.substring(0, pos).trim();
				String textUnit = value.substring(pos + 1, end).trim();
				valueUnit = getTimeUnit(textUnit);
				if (valueUnit == null) {
					throw new ValueException(textUnit + " unknown unit!");
				}
			} else {
				throw new ValueException(value + " doesn't match value[unit]!");
			}
		} else {
			char last = value.charAt(value.length() - 1);
			if (!Character.isDigit(last)) {
				TimeUnit unit = getTimeUnit(value);
				if (unit != null) {
					valueUnit = unit;
					num = value.substring(0, value.length() - getTimeUnitAsText(unit).length()).trim();
				}
			}
		}
		long time = Long.parseLong(num);
		return TimeUnit.NANOSECONDS.convert(time, valueUnit);
	}

	/**
	 * Gets time unit as text.
	 * 
	 * @param unit time unit
	 * @return time unit as text
	 */
	public static String getTimeUnitAsText(TimeUnit unit) {
		switch (unit) {
		case NANOSECONDS:
			return "ns";
		case MICROSECONDS:
			return "ys";
		case MILLISECONDS:
			return "ms";
		case SECONDS:
			return "s";
		case MINUTES:
			return "min";
		case HOURS:
			return "h";
		case DAYS:
			return "d";
		}
		return "";
	}

	/**
	 * Gets time unit
	 * 
	 * @param timeUnitText textual time unit
	 * @return time unit, {@code null}, if not supported
	 */
	public static TimeUnit getTimeUnit(String timeUnitText) {
		String matchUnitText = "";
		TimeUnit matchingUnit = null;
		for (TimeUnit unit : TimeUnit.values()) {
			String text = getTimeUnitAsText(unit);
			if (!text.isEmpty()) {
				if (text.equals(timeUnitText)) {
					return unit;
				} else if (timeUnitText.endsWith(text) && text.length() > matchUnitText.length()) {
					matchingUnit = unit;
					matchUnitText = text;
				}
			}
		}
		return matchingUnit;
	}
}
