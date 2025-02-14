/********************************************************************************
 * Copyright (c) 2025 Contributors to the Eclipse Foundation
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
package org.eclipse.californium.scandium.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.TlsKeyLog;
import org.eclipse.californium.scandium.dtls.Random;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TLSKEYLOG file.
 * <p>
 * The file contains sensitive keys for encryption! Use it with reasonable care!
 * 
 * @see <a href="https://tlswg.org/sslkeylogfile/draft-ietf-tls-keylogfile.html"
 *      target="_blank"> draft-ietf-tls-keylogfile</a>
 * @since 4.0
 */
public class TlsKeyLogFile implements TlsKeyLog {

	/**
	 * The logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(TlsKeyLogFile.class);

	private static final Map<String, TlsKeyLogFile> map = new HashMap<>(16);

	private File file;
	private OutputStream out;

	public TlsKeyLogFile(String filename) {
		file = new File(filename);
		open();
	}

	public synchronized OutputStream open() {
		delete();
		try {
			out = new FileOutputStream(file);
			LOGGER.info("TLSKEYLOG: {} created", file.getAbsolutePath());
		} catch (FileNotFoundException e) {
			LOGGER.warn("TLSKEYLOG: create", e);
		}
		return out;
	}

	public synchronized void delete() {
		close();
		file.delete();
	}

	private synchronized OutputStream getOutputStream() {
		return out;
	}

	private byte[] format(Random clientRandom, SecretKey masterSecret) {
		StringBuffer buffer = new StringBuffer("CLIENT_RANDOM ");
		buffer.append(clientRandom.getAsString());
		buffer.append(' ');
		buffer.append(StringUtil.byteArray2Hex(masterSecret.getEncoded()));
		buffer.append(StringUtil.lineSeparator());
		return buffer.toString().getBytes();
	}

	public void append(InetSocketAddress source, Principal principal, Random clientRandom, SecretKey masterSecret) {
		OutputStream out = getOutputStream();
		if (out != null) {
			byte[] line = format(clientRandom, masterSecret);
			synchronized (this) {
				if (file.length() > 10000) {
					out = open();
					if (out == null) {
						return;
					}
				}
				try {
					out.write(line);
					out.flush();
				} catch (IOException e) {
					LOGGER.warn("TLSKEYLOG: write", e);
				}
			}
		}
	}

	public synchronized void close() {
		OutputStream out = this.out;
		if (out != null) {
			this.out = null;
			try {
				out.close();
			} catch (IOException e) {
				LOGGER.warn("TLSKEYLOG: close", e);
			}
		}
	}

	public static TlsKeyLogFile get(String name) {
		synchronized (map) {
			TlsKeyLogFile file = map.get(name);
			if (file == null) {
				file = new TlsKeyLogFile(name);
				map.put(name, file);
			}
			return file;
		}
	}

	public static void closeAll() {
		synchronized (map) {
			for (TlsKeyLogFile file : map.values()) {
				file.delete();
			}
		}
	}

	static {
		Runtime.getRuntime().addShutdownHook(new Thread("TLSKEYLOG-SHUTDOWN") {

			@Override
			public void run() {
				closeAll();
			}
		});
	}
}
