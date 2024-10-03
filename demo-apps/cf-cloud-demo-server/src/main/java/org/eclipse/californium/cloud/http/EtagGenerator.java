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
package org.eclipse.californium.cloud.http;

import java.security.MessageDigest;
import java.util.List;

import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalMessageDigest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.HttpExchange;

/**
 * HTTP-ETAG generator.
 * 
 * @since 3.13
 */
@SuppressWarnings("restriction")
public class EtagGenerator {

	private static final Logger LOGGER = LoggerFactory.getLogger(EtagGenerator.class);

	/**
	 * Name of ETAG header.
	 */
	private static final String ETAG_HEADER = "ETag";
	/**
	 * Name of if-none-match header.
	 */
	private static final String IF_NONE_MATCH_HEADER = "If-None-Match";
	/**
	 * Hash algorithm for ETAG.
	 */
	private static final String ETAG_ALGORITHM = "MD5";
	/**
	 * Thread local message digest for ETAG.
	 */
	private static final ThreadLocalMessageDigest ETAG = new ThreadLocalMessageDigest(ETAG_ALGORITHM);

	/**
	 * Set ETAG for http response.
	 * 
	 * @param exchange http exchange.
	 * @param payload payload to calculate ETAG.
	 * @return {@code true}, if payload matches provided ETAG. {@code false},
	 *         otherwise.
	 */
	public static boolean setEtag(HttpExchange exchange, byte[] payload) {
		MessageDigest md = ETAG.current();
		md.reset();
		String etag = StringUtil.byteArray2Hex(md.digest(payload)).toLowerCase();
		exchange.getResponseHeaders().set(ETAG_HEADER, etag);
		List<String> etags = exchange.getRequestHeaders().get(IF_NONE_MATCH_HEADER);
		if (etags != null) {
			if (etags.contains(etag)) {
				LOGGER.info("ETAG matching");
				return true;
			} else {
				LOGGER.info("ETAG not matching");
			}
		} else {
			LOGGER.info("ETAG not provided");
		}
		return false;
	}
}
