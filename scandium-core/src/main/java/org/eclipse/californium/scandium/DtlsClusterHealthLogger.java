/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
package org.eclipse.californium.scandium;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Cluster health implementation using counter and logging for results.
 * 
 * @since 2.5
 */
public class DtlsClusterHealthLogger extends DtlsHealthLogger implements DtlsClusterHealth {

	/**
	 * Message dropping is accessed via {@link #getByKey(String)}.
	 * 
	 * @since 3.1
	 */
	public static final String DROPPED_INTERNAL_UDP_MESSAGES = "dropped internal udp";

	private final SimpleCounterStatistic forwardedMessage = new SimpleCounterStatistic("forwarded", align);
	private final SimpleCounterStatistic processedForwardedMessage = new SimpleCounterStatistic("process forwarded",
			align);
	private final SimpleCounterStatistic badForwardMessage = new SimpleCounterStatistic("bad forward", align);
	private final SimpleCounterStatistic dropForwardMessage = new SimpleCounterStatistic("drop forward", align);
	private final SimpleCounterStatistic backwardedMessage = new SimpleCounterStatistic("backwarded", align);
	private final SimpleCounterStatistic sendBackwardedMessage = new SimpleCounterStatistic("send backwarded", align);
	private final SimpleCounterStatistic badBackwardMessage = new SimpleCounterStatistic("bad backward", align);
	private final SimpleCounterStatistic dropBackwardMessage = new SimpleCounterStatistic("drop backward", align);

	private final SimpleCounterStatistic sendingClusterManagementMessage = new SimpleCounterStatistic(
			"sent cluster mgmt", align);
	private final SimpleCounterStatistic receivingClusterManagementMessage = new SimpleCounterStatistic(
			"recv cluster mgmt", align);
	private final SimpleCounterStatistic droppedInternalMessages = new SimpleCounterStatistic(
			DROPPED_INTERNAL_UDP_MESSAGES, align);

	/**
	 * Create passive dtls cluster health logger.
	 */
	public DtlsClusterHealthLogger() {
		this("");
	}

	/**
	 * Create passive dtls cluster health logger with logging tag.
	 * 
	 * @param tag logging tag
	 */
	public DtlsClusterHealthLogger(String tag) {
		super(tag);
		init();
	}

	/**
	 * Create active dtls cluster health logger with logging tag.
	 * 
	 * @param tag logging tag
	 * @param interval interval. {@code 0} to disable actively calling
	 *            {@link #dump()}.
	 * @param unit time unit of interval
	 * @param executor executor to schedule active calls of {@link #dump()}.
	 * @throws NullPointerException if executor is {@code null}
	 * @since 3.0 (added unit)
	 * @deprecated use {@link DtlsClusterHealthLogger#DtlsClusterHealthLogger(String)}
	 *             instead and call {@link #dump()} externally.
	 */
	public DtlsClusterHealthLogger(String tag, int interval, TimeUnit unit, ScheduledExecutorService executor) {
		super(tag, interval, unit, executor);
		init();
	}

	private void init() {
		add(forwardedMessage);
		add(processedForwardedMessage);
		add(badForwardMessage);
		add(dropForwardMessage);
		add(backwardedMessage);
		add(sendBackwardedMessage);
		add(badBackwardMessage);
		add(dropBackwardMessage);
		add(sendingClusterManagementMessage);
		add(receivingClusterManagementMessage);
		add(droppedInternalMessages);
	}

	protected boolean isUsed() {
		return super.isUsed() || forwardedMessage.isUsed() || dropForwardMessage.isUsed() || badForwardMessage.isUsed();
	}

	protected void dump(String head, StringBuilder log) {
		String eol = StringUtil.lineSeparator();
		log.append(eol);
		log.append(head).append(forwardedMessage).append(eol);
		log.append(head).append(processedForwardedMessage).append(eol);
		log.append(head).append(badForwardMessage).append(eol);
		log.append(head).append(dropForwardMessage).append(eol);
		log.append(head).append(backwardedMessage).append(eol);
		log.append(head).append(sendBackwardedMessage).append(eol);
		log.append(head).append(badBackwardMessage).append(eol);
		log.append(head).append(dropBackwardMessage).append(eol);
		log.append(head).append(sendingClusterManagementMessage).append(eol);
		log.append(head).append(receivingClusterManagementMessage);
		if (droppedInternalMessages.isStarted()) {
			log.append(eol).append(head).append(droppedInternalMessages);
		}
	}

	@Override
	public void forwardMessage() {
		forwardedMessage.increment();
	}

	@Override
	public void backwardMessage() {
		backwardedMessage.increment();
	}

	@Override
	public void processForwardedMessage() {
		processedForwardedMessage.increment();
	}

	@Override
	public void sendBackwardedMessage() {
		sendBackwardedMessage.increment();
	}

	@Override
	public void dropForwardMessage() {
		dropForwardMessage.increment();
	}

	@Override
	public void dropBackwardMessage() {
		dropBackwardMessage.increment();
	}

	@Override
	public void badForwardMessage() {
		badForwardMessage.increment();
	}

	@Override
	public void badBackwardMessage() {
		badBackwardMessage.increment();
	}

	@Override
	public void sendingClusterManagementMessage() {
		sendingClusterManagementMessage.increment();
	}

	@Override
	public void receivingClusterManagementMessage() {
		receivingClusterManagementMessage.increment();
	}

}
