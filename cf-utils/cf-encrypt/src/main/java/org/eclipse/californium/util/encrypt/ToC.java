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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Base64.Encoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Convert PEM into C-header.
 * 
 * @since 4.0
 */
public class ToC {
	/**
	 * Pattern for begin tag.
	 */
	private static final Pattern BEGIN_PATTERN = Pattern.compile("^\\-+BEGIN\\s+([\\w\\s]+)\\-+$");

	/**
	 * Pattern for end tag.
	 */
	private static final Pattern END_PATTERN = Pattern.compile("^\\-+END\\s+([\\w\\s]+)\\-+$");

	private static final String MARKER = "-----";
	private static final String BEGIN = "BEGIN ";
	private static final String END = "END ";
	private static final String PRIVATE_KEY = "PRIVATE KEY";
	private static final String PUBLIC_KEY = "PUBLIC KEY";
	private static final String CERTIFICATE = "CERTIFICATE";

	private static void usage() {
		System.out.println("usage:  <file>.pem [<out>]");
		System.out.println("usage:  <file>.p12 [<out>] --alias <alias> --pass <password> [--keypass <key-password]");
		System.out.println("   <out>: <file> (for .pem)");
		System.out.println("   <out>: <alias> (for .p12)");
		System.out.println("   <out.files>: <out>_<pem-tag>.h");
	}

	public static void main(String[] args) {
		File file = null;
		String out = null;
		String alias = null;
		char[] pass = null;
		char[] keyPass = null;

		for (int index = 0; index < args.length; ++index) {
			if (args[index].equals("--alias")) {
				if (alias != null) {
					throw new IllegalArgumentException("--alias already provided!");
				}
				++index;
				if (index < args.length) {
					alias = args[index];
				} else {
					throw new IllegalArgumentException("--alias missing argument!");
				}
			} else if (args[index].equals("--pass")) {
				if (pass != null) {
					throw new IllegalArgumentException("--pass already provided!");
				}
				++index;
				if (index < args.length) {
					pass = args[index].toCharArray();
				} else {
					throw new IllegalArgumentException("--pass missing argument!");
				}
			} else if (args[index].equals("--keypass")) {
				if (keyPass != null) {
					throw new IllegalArgumentException("--keypass already provided!");
				}
				++index;
				if (index < args.length) {
					keyPass = args[index].toCharArray();
				} else {
					throw new IllegalArgumentException("--keypass missing argument!");
				}
			} else {
				if (file == null) {
					file = new File(args[index]);
				} else if (out == null) {
					out = args[index];
				} else {
					throw new IllegalArgumentException("too many arguments! " + args[index]);
				}
			}
		}

		if (file == null) {
			throw new IllegalArgumentException("file missing!");
		}
		String name = file.getName();
		if (name.endsWith(".pem")) {
			if (alias != null) {
				throw new IllegalArgumentException("--alias not supported for .pem!");
			}
			if (pass != null) {
				throw new IllegalArgumentException("--pass not supported for .pem!");
			}
			if (keyPass != null) {
				throw new IllegalArgumentException("--keypass not supported for .pem!");
			}
			if (out == null) {
				out = name.substring(0, name.length() - 4);
			}
			exportPEM(file, out);
		} else if (name.endsWith(".p12")) {
			if (alias == null) {
				throw new IllegalArgumentException("--alias missing!");
			}
			if (pass == null) {
				throw new IllegalArgumentException("--pass missing!");
			}
			if (out == null) {
				out = alias;
			}
			if (keyPass == null) {
				keyPass = pass;
			}
			exportP12(file, out, alias, pass, keyPass);
		} else {
			usage();
			System.exit(1);
		}
	}

	private static final Integer ZERO = 0;
	private static Map<String, Integer> counters = new HashMap<>();
	private static List<String> names = new ArrayList<>();

	private static String getFilename(String out, String tag) {
		String name = out + "_" + tag.toLowerCase().replace(' ', '_');
		Integer cur = counters.putIfAbsent(tag.toLowerCase(), ZERO);
		if (cur != null) {
			cur += 1;
			counters.putIfAbsent(tag.toLowerCase(), cur);
			name = name + "_" + cur;
		}
		name += ".h";
		names.add("'" + name + "'");
		return name;
	}

	public static void exportPEM(File file, String out) {
		try {
			String line = null;

			try (BufferedReader reader = new BufferedReader(
					new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
				String tag = null;
				while ((line = reader.readLine()) != null) {
					if (tag == null) {
						Matcher matcher = BEGIN_PATTERN.matcher(line);
						if (matcher.matches()) {
							tag = matcher.group(1);
						}
					}
					if (tag != null) {
						String name = getFilename(out, tag);
						System.out.println(tag + " => " + name);
						try (BufferedWriter writer = new BufferedWriter(
								new OutputStreamWriter(new FileOutputStream(name), StandardCharsets.UTF_8))) {
							writeCLine(writer, line);
							while ((line = reader.readLine()) != null) {
								writeCLine(writer, line);
								Matcher matcher = END_PATTERN.matcher(line);
								if (matcher.matches()) {
									String end = matcher.group(1);
									if (!end.equals(tag)) {
										System.err.println("Stop? " + line);
										System.err.println("   expected " + tag);
									}
									tag = null;
									break;
								}
							}
						}
					}
				}
			}
			System.out.println("Converted '" + file.getCanonicalPath() + "' to " + names);
			return;
		} catch (FileNotFoundException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println(e.getMessage());
		} catch (IllegalArgumentException e) {
			System.err.println(e.getMessage());
		}
		System.err.println();
		try {
			Thread.sleep(100);
		} catch (InterruptedException e1) {
		}

		usage();
		System.exit(1);
	}

	public static void exportP12(File file, String out, String alias, char[] pass, char[] keyPass) {
		try {
			System.out.println("Extract alias '" + alias + "'");

			Credentials credentials = SslContextUtil.loadCredentials(file.getCanonicalPath(), alias, pass, keyPass);
			if (credentials.getPrivateKey() != null) {
				String name = getFilename(out, PRIVATE_KEY);
				try (BufferedWriter writer = new BufferedWriter(
						new OutputStreamWriter(new FileOutputStream(name), StandardCharsets.UTF_8))) {
					writeCLine(writer, MARKER + BEGIN + PRIVATE_KEY + MARKER);
					writeCBase64(writer, credentials.getPrivateKey().getEncoded());
					writeCLine(writer, MARKER + END + PRIVATE_KEY + MARKER);
				}
			}
			if (credentials.getCertificateChain() != null) {
				X509Certificate[] chain = credentials.getCertificateChain();
				for (int index = 0; index < chain.length; ++index) {
					X509Certificate certificate = chain[index];
					String tag = CERTIFICATE;
					if (0 < index && index == chain.length - 1) {
						tag = "CA " + CERTIFICATE;
					}
					String name = getFilename(out, tag);
					try (BufferedWriter writer = new BufferedWriter(
							new OutputStreamWriter(new FileOutputStream(name), StandardCharsets.UTF_8))) {
						writeLine(writer, "/* Certificate " + (index + 1) + " */");
						writeCLine(writer, MARKER + BEGIN + CERTIFICATE + MARKER);
						writeCBase64(writer, certificate.getEncoded());
						writeCLine(writer, MARKER + END + CERTIFICATE + MARKER);
					}
				}
				if (chain.length > 1) {
					X509Certificate certificate = chain[chain.length - 1];
					String name = out + "_ca_certificate.pem";
					names.add("'" + name + "'");
					try (BufferedWriter writer = new BufferedWriter(
							new OutputStreamWriter(new FileOutputStream(name), StandardCharsets.UTF_8))) {
						writeLine(writer, MARKER + BEGIN + CERTIFICATE + MARKER);
						writeBase64(writer, certificate.getEncoded());
						writeLine(writer, MARKER + END + CERTIFICATE + MARKER);
					}
				}
				X509Certificate certificate = chain[0];
				String name = out + "_public_key.pem";
				names.add("'" + name + "'");
				try (BufferedWriter writer = new BufferedWriter(
						new OutputStreamWriter(new FileOutputStream(name), StandardCharsets.UTF_8))) {
					writeLine(writer, MARKER + BEGIN + PUBLIC_KEY + MARKER);
					writeBase64(writer, certificate.getPublicKey().getEncoded());
					writeLine(writer, MARKER + END + PUBLIC_KEY + MARKER);
				}
			}
			System.out.println("Converted '" + file.getCanonicalPath() + "' to " + names);
			return;
		} catch (IOException e) {
			System.err.println();
			System.err.println(e.getMessage());
			if (e.getMessage().contains("parseAlgParameters failed:")) {
				String version = System.getProperty("java.version");
				String[] split = version.split("\\.", 2);
				if (split[0].length() < 2) {
					System.err.println("Please use at least java 11!");
				}
			}
		} catch (IllegalArgumentException e) {
			System.err.println();
			System.err.println(e.getMessage());
		} catch (GeneralSecurityException e) {
			System.err.println();
			System.err.println(e.getMessage());
		}
		System.err.println();
		try {
			Thread.sleep(100);
		} catch (InterruptedException e1) {
		}

		usage();
		System.exit(1);
	}

	private static void writeCBase64(BufferedWriter writer, byte[] data) throws IOException {
		String[] lines = base64(data);
		for (String line : lines) {
			writeCLine(writer, line);
		}
	}

	private static void writeBase64(BufferedWriter writer, byte[] data) throws IOException {
		String[] lines = base64(data);
		for (String line : lines) {
			writeLine(writer, line);
		}
	}

	private static void writeCLine(BufferedWriter writer, String line) throws IOException {
		writer.write("\"" + line + "\\n\"");
		writer.newLine();
	}

	private static void writeLine(BufferedWriter writer, String line) throws IOException {
		writer.write(line);
		writer.newLine();
	}

	private static String[] base64(byte[] data) throws IOException {
		Encoder mimeEncoder = Base64.getMimeEncoder(64, StringUtil.lineSeparator().getBytes(StandardCharsets.UTF_8));
		String base64 = mimeEncoder.encodeToString(data);
		return base64.split(StringUtil.lineSeparator());
	}

}
