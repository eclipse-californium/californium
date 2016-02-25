/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 ******************************************************************************/
package org.eclipse.californium.core.network.interceptors;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;

/**
 * The OriginTracer logs remote addresses to files in the "origin-trace"
 * sub-folder. The data is used for the Eclipse IoT metrics.
 */
public class OriginTracer implements MessageInterceptor {

	private static final Logger LOGGER = Logger.getLogger(OriginTracer.class.getCanonicalName());
	private static final SimpleDateFormat dateFormat = new SimpleDateFormat("[yyyy-MM-dd HH:mm:ss]");

	static {
		final FileHandler fh;

		try {
			String month = new SimpleDateFormat("yyyy-MM").format(new Date());
			fh = new FileHandler("origin-trace/origin-trace-" + month + ".txt", true);
			SimpleFormatter formatter = new SimpleFormatter() {
				public String format(LogRecord record) {
					String message = formatMessage(record);
					return String.format("%s\t%s%s", dateFormat.format(new Date()), message, System.lineSeparator());
				}
			};
			fh.setFormatter(formatter);

			LOGGER.addHandler(fh);

			// Java 8 does not remove lock if not FileHandler is not closed
			Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
				public void run() {
					fh.close();
				}
			}));
		} catch (IOException e) {
			System.err.println("origin-tracer directory does not exist. Skipping origin traces...");
		}
	}

	@Override
	public void receiveRequest(Request request) {
		LOGGER.log(Level.INFO, "{0}", request.getSource());
	}

	@Override
	public void sendRequest(Request request) {
		// nothing to do
	}

	@Override
	public void sendResponse(Response response) {
		// nothing to do
	}

	@Override
	public void sendEmptyMessage(EmptyMessage message) {
		// nothing to do
	}

	@Override
	public void receiveResponse(Response response) {
		// nothing to do
	}

	@Override
	public void receiveEmptyMessage(EmptyMessage message) {
		// only log pings
		if (message.getType() == Type.CON)
			LOGGER.log(Level.INFO, "{0}", message.getSource());
	}
}
