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

import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Cluster health implementation using counter and logging for results.
 * 
 * @since 2.5
 */
public class DtlsClusterHealthLogger extends DtlsHealthLogger implements DtlsClusterHealth {

	private final SimpleCounterStatistic forwardedMessage = new SimpleCounterStatistic("forwarded", align);
	private final SimpleCounterStatistic processedForwardedMessage = new SimpleCounterStatistic("process-forwarded", align);
	private final SimpleCounterStatistic backwardedMessage = new SimpleCounterStatistic("backwarded", align);
	private final SimpleCounterStatistic sendBackwardedMessage = new SimpleCounterStatistic("send-backwarded", align);

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
	 * @param interval interval in seconds. {@code 0} to disable actively
	 *            calling {@link #dump()}.
	 * @param executor executor to schedule active calls of {@link #dump()}.
	 */
	public DtlsClusterHealthLogger(String tag, int interval, ScheduledExecutorService executor) {
		super(tag, interval, executor);
		init();
	}

	private void init() {
		add(forwardedMessage);
		add(backwardedMessage);
	}

	protected void dump(String head, StringBuilder log) {
		String eol = StringUtil.lineSeparator();
		log.append(eol);
		log.append(head).append(forwardedMessage).append(eol);
		log.append(head).append(processedForwardedMessage).append(eol);
		log.append(head).append(backwardedMessage).append(eol);
		log.append(head).append(sendBackwardedMessage);
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

}
