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

package org.eclipse.californium.util.encrypt;

import java.io.IOException;
import java.util.Arrays;

import org.eclipse.californium.elements.exception.ConnectorException;

/**
 * Main starter class for jar execution.
 * 
 * @since 4.0
 */
public class Utilities {

	private static final String FILE = "file";
	private static final String KEY = "key";
	private static final String TOC = "toc";

	public static void main(String[] args) throws IOException, ConnectorException, InterruptedException {
		String start = args.length > 0 ? args[0] : null;
		if (start != null) {
			String[] args2 = Arrays.copyOfRange(args, 1, args.length);
			if (FILE.equals(start)) {
				Encrypt.main(args2);
				return;
			} else if (KEY.equals(start)) {
				Dump.main(args2);
				return;
			} else if (TOC.equals(start)) {
				Dump.main(args2);
				return;
			}
		}
		System.out.println("\nCalifornium (Cf) Utility-Starter");
		System.out.println("(c) 2024, Contributors to the Eclipse Foundation");
		System.out.println();
		System.out.println("Usage: " + Utilities.class.getSimpleName() + " (" + FILE + "|" + KEY + "|" + TOC + ")");
		if (start != null) {
			System.out.println("   '" + start + "' is not supported!");
		}
		System.exit(-1);
	}
}
