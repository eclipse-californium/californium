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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Dump private or public key as hexadecimal or base64 string.
 * 
 * @since 4.0
 */
public class Dump {
	private static void usage() {
		System.out.println("usage:  [(--private-key|--public-key)] [(--hex|--base64)] [--raw] <file>");
		System.out.println("       --private-key  : dump private key");
		System.out.println("       --public-key   : dump public key (default)");
		System.out.println("       --hex          : dump key in hexadecimal");
		System.out.println("       --base64       : dump key in base 64 (default)");
		System.out.println("       --raw          : dump raw key (skip ASN.1 header).");
	}

	public static void main(String[] args) {
		try {
			boolean raw = false;
			Boolean mode = null;
			Boolean encoding = null;
			String file = null;

			for (int index = 0; index < args.length; ++index) {
				if (args[index].equals("--private-key")) {
					if (mode != null && !mode) {
						throw new IllegalArgumentException("--public-key also provided!");
					}
					mode = true;
				} else if (args[index].equals("--public-key")) {
					if (mode != null && mode) {
						throw new IllegalArgumentException("--private-key also provided!");
					}
					mode = false;
				} else if (args[index].equals("--hex")) {
					if (encoding != null && !encoding) {
						throw new IllegalArgumentException("--base64 also provided!");
					}
					encoding = true;
				} else if (args[index].equals("--base64")) {
					if (encoding != null && encoding) {
						throw new IllegalArgumentException("--hex also provided!");
					}
					encoding = false;
				} else if (args[index].equals("--raw")) {
					raw = true;
				} else {
					if (file != null) {
						throw new IllegalArgumentException("file already provided!");
					}
					file = args[index];
				}
			}
			if (file == null) {
				System.err.println("Misssing file!");
			} else {
				byte[] key = null;
				if (Boolean.TRUE == mode) {
					PrivateKey privateKey = SslContextUtil.loadPrivateKey(file, null, null, null);
					key = privateKey.getEncoded();
					if (raw && privateKey instanceof ECKey) {
						int keySize = getKeySize((ECKey) privateKey);
						key = Arrays.copyOfRange(key, key.length - keySize, key.length);
					}
				} else {
					PublicKey publicKey = SslContextUtil.loadPublicKey(file, null, null);
					key = publicKey.getEncoded();
					if (raw && publicKey instanceof ECKey) {
						int keySize = getKeySize((ECKey) publicKey);
						key = Arrays.copyOfRange(key, key.length - (keySize * 2), key.length);
					}
				}
				if (key != null) {
					if (Boolean.TRUE == encoding) {
						System.out.println(":0x" + StringUtil.byteArray2Hex(key));
					} else {
						System.out.println(StringUtil.byteArrayToBase64(key));
					}
				}
				return;
			}
		} catch (GeneralSecurityException x) {
			System.err.println(x.getMessage());
		} catch (ArrayIndexOutOfBoundsException x) {
			System.err.println("Misssing parameter for " + args[args.length - 1]);
		} catch (IllegalArgumentException x) {
			System.err.println(x.getMessage());
		} catch (FileNotFoundException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
		usage();
		System.exit(1);
	}

	private static int getKeySize(ECKey key) {
		EllipticCurve curve = key.getParams().getCurve();
		return (curve.getField().getFieldSize() + Byte.SIZE - 1) / Byte.SIZE;
	}

}
