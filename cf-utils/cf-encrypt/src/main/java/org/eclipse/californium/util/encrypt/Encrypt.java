/********************************************************************************
 * Copyright (c) 2023 Contributors to the Eclipse Foundation
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.util.EncryptedStreamUtil;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Simple test NAT.
 *
 * Supports interactive reassign of local mapped addresses.
 */
public class Encrypt {

	private static void usage() {
		System.out.println("usage:  --password64 <password-base64> [--out <file>]");
		System.out.println("        [(--encrypt [--cipher <cipher>]|--decrypt)] [--in] <file>");
		System.out.println("       --password64   : password base 64 encoded");
		System.out.println("       --encrypt      : encrypt file. Default.");
		System.out.println("         --cipher     : cipher to encrypt file. Default \"AES/GCM/128\" or ");
		System.out.println("                        \"AES/CBC/128\", if GCM is not supported by the JCE;");
		System.out.println("       --decrypt      : decrypt file");
		System.out.println("       --out          : output file name. Default replaces input file.");
		System.out.println("       --in           : input file name.");
	}

	@SuppressWarnings("resource")
	public static void main(String[] args) {
		try {
			String cipher = null;
			File file = null;
			File out = null;
			File temp = null;
			SecretKey password = null;
			Boolean encrypt = null;

			for (int index = 0; index < args.length; ++index) {
				if (args[index].equals("--password64")) {
					if (password != null) {
						throw new IllegalArgumentException("--password64 already provided!");
					}
					password = new SecretKeySpec(StringUtil.base64ToByteArray(args[++index]), "PASSWORD");
				} else if (args[index].equals("--out")) {
					if (out != null) {
						throw new IllegalArgumentException("--out already provided!");
					}
					out = new File(args[++index]);
				} else if (args[index].equals("--cipher")) {
					if (cipher != null) {
						throw new IllegalArgumentException("--cipher already provided!");
					}
					cipher = args[++index];
				} else if (args[index].equals("--encrypt")) {
					if (encrypt != null) {
						throw new IllegalArgumentException("--encrypt or --decrypt already provided!");
					}
					encrypt = true;
				} else if (args[index].equals("--decrypt")) {
					if (encrypt != null) {
						throw new IllegalArgumentException("--encrypt or --decrypt already provided!");
					}
					encrypt = false;
				} else if (args[index].equals("--in")) {
					if (file != null) {
						throw new IllegalArgumentException("file already provided!");
					}
					file = new File(args[++index]);
				} else if (args[index].startsWith("--")) {
					throw new IllegalArgumentException(args[index] + " not supported!");
				} else {
					if (file != null) {
						throw new IllegalArgumentException("file already provided!");
					}
					file = new File(args[index]);
				}
			}
			if (password == null) {
				System.err.println("Misssing --password64");
			} else if (file == null) {
				System.err.println("Misssing [--in] file");
			} else {
				EncryptedStreamUtil util = new EncryptedStreamUtil();
				if (encrypt == null) {
					encrypt = true;
				}
				if (!encrypt && cipher != null) {
					throw new IllegalArgumentException("Provided cipher " + cipher + " is ignored with decrypt!");
				}
				if (out == null) {
					temp = createUnique(file, ".temp");
					out = temp;
				}
				String mode = encrypt ? "Encrypted " : "Decrypted ";
				OutputStream os = null;
				InputStream is = null;
				try {
					os = new FileOutputStream(out);
					is = new FileInputStream(file);
					if (encrypt) {
						if (cipher != null) {
							util.setWriteCipher(cipher);
						} else {
							cipher = util.getWriteCipher();
						}
						os = util.prepare(os, password);
					} else {
						is = util.prepare(is, password);
						cipher = util.getReadCipher();
					}
					byte[] buffer = new byte[1024 * 1024];
					int len = 0;
					while ((len = is.read(buffer)) >= 0) {
						if (len > 0) {
							os.write(buffer, 0, len);
						}
					}
				} finally {
					if (os != null) {
						os.close();
					}
					if (is != null) {
						is.close();
					}
				}
				long size = file.length();
				if (temp != null) {
					File backup = createUnique(file, ".orig");
					file.renameTo(backup);
					temp.renameTo(file);
					System.out.println(mode + size + " bytes in " + file + " using " + cipher);
				} else {
					System.out.println(mode + size + " bytes from " + file + " to " + out + " using " + cipher);
				}
				return;
			}
		} catch (ArrayIndexOutOfBoundsException ex) {
			System.err.println("Misssing parameter for " + args[args.length - 1]);
		} catch (IllegalArgumentException ex) {
			System.err.println(ex.getMessage());
		} catch (FileNotFoundException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
		usage();
		System.exit(1);
	}

	private static File createUnique(File file, String ending) {
		int index = 1;
		File result = new File(file.getPath() + ending);
		while (result.exists()) {
			result = new File(file.getPath() + ending + "." + index++);
		}
		return result;
	}
}
