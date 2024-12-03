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
package org.eclipse.californium.cloud.s3.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.DestroyFailedException;

import org.eclipse.californium.cloud.util.ResourceParser;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Web application user parser.
 * <p>
 * Format:
 * 
 * <pre>
 * {@code # <comment>}
 * 
 * {@code <user-name>[.pw]=<password>}
 * {@code [[<user-name>].s3=<s3AccessKeyId>,<s3AccessKeySecret>]}
 * {@code [[<user-name>].config=<config>]}
 * {@code [[<user-name>].groups=<group1>,<group2>,..]}
 * 
 * {@code [*.s3=<s3AccessKeyId>,<s3AccessKeySecret>]}
 * </pre>
 * 
 * The {@code password}, the {@code s3AccessKeyId}, and the
 * {@code s3AccessKeySecret} may be provided in base 64 or included as plain
 * text in single- ({@code '}) or double-quotes ({@code "}). {@code config} may
 * be provided plain or included in single- ({@code '}) or double-quotes
 * ({@code "}). The {@code groups} is a {@code ','} separated list of group
 * names, each either in plain or included in single- ({@code '}) or
 * double-quotes ({@code "}). An entry with {@code *.s3} is used to setup the
 * default S3 credentials for user definitions without explicit {@code .s3}
 * definition.
 * <p>
 * Example:
 * 
 * <pre>
 * {@code # default S3 credentials}
 * {@code *.s3='<S3-access-key-id-default>','<S3-access-key-secret-default>'}
 * 
 * {@code # User with default S3 credentials}
 * {@code User1='secret'}
 * {@code .config=user}
 * 
 * {@code # User, base 64 password and S3 credentials}
 * {@code User2=bW9yZSBzZWNyZXQ=}
 * {@code .config=admin}
 * {@code .s3='<S3-access-key-id-user2>','<S3-access-key-secret-user2>'}
 * {@code .groups=Demo,Environment-Sensor}
 * 
 * </pre>
 * 
 * @since 3.12
 */
public class WebAppUserParser implements ResourceParser<WebAppUserParser> {

	private static final Logger LOGGER = LoggerFactory.getLogger(WebAppUserParser.class);

	/**
	 * Postfix in header for password.
	 */
	public static final String PW_POSTFIX = ".pw";
	/**
	 * Postfix in header for S3 credentials.
	 */
	public static final String S3_POSTFIX = ".s3";
	/**
	 * Postfix in header for groups.
	 */
	public static final String GROUPS_POSTFIX = ".groups";
	/**
	 * Postfix in header for "Single Page Application" configuration store.
	 */
	public static final String CONFIG_POSTFIX = ".config";

	/**
	 * Map of user names and credentials.
	 */
	private final Map<String, WebAppUser> map = new ConcurrentHashMap<>();
	/**
	 * Default S3 credentials.
	 */
	private WebAppUser s3Default;
	/**
	 * {@code true} to use case sensitive names, {@code false}, otherwise.
	 */
	private final boolean caseSensitiveNames;
	/**
	 * {@code true} if credentials are destroyed.
	 */
	private volatile boolean destroyed;

	/**
	 * Create credentials map.
	 * 
	 * @param caseSensitiveNames {@code true} to use case sensitive names,
	 *            {@code false}, otherwise.
	 */
	public WebAppUserParser(boolean caseSensitiveNames) {
		this.caseSensitiveNames = caseSensitiveNames;
	}

	/**
	 * Get key from name.
	 * 
	 * @param name name of entry
	 * @return key from name
	 * @see #caseSensitiveNames
	 */
	private String getKey(String name) {
		String key = name == null ? "" : name;
		if (!caseSensitiveNames && key != null) {
			key = key.toLowerCase();
		}
		return key;
	}

	/**
	 * Match names considering {@link #caseSensitiveNames}.
	 * 
	 * @param name1 first name to match
	 * @param name2 second name to match
	 * @return {@code true}, if names are matching, {@code false}, otherwise.
	 */
	private boolean match(String name1, String name2) {
		if (caseSensitiveNames) {
			return name1.equals(name2);
		} else {
			return name1.equalsIgnoreCase(name2);
		}
	}

	/**
	 * Get prefix from id.
	 * 
	 * @param id id
	 * @param postfix postfix to be removed from id
	 * @return either the unchanged id, or the id with the postfix tail removed.
	 * @see StringUtil#truncateTail(boolean, String, String)
	 */
	private String prefix(String id, String postfix) {
		return StringUtil.truncateTail(caseSensitiveNames, id, postfix);
	}

	/**
	 * Checks, if id is a name.
	 * 
	 * The id is a name, if it ends with {@link #PW_POSTFIX}, or if it doesn't
	 * end with {@link #S3_POSTFIX}, {@link #GROUPS_POSTFIX} nor
	 * {@link #CONFIG_POSTFIX}.
	 * 
	 * @param id id to check
	 * @return {@code true}, if id complies with a name, {@code false},
	 *         otherwise.
	 */
	private boolean isName(String id) {
		String name = prefix(id, PW_POSTFIX);
		if (name != id) {
			return true;
		}
		name = prefix(id, S3_POSTFIX);
		if (name != id) {
			return !map.containsKey(getKey(name));
		}
		name = prefix(id, GROUPS_POSTFIX);
		if (name != id) {
			return !map.containsKey(getKey(name));
		}
		name = prefix(id, CONFIG_POSTFIX);
		if (name != id) {
			return !map.containsKey(getKey(name));
		}
		return true;
	}

	/**
	 * Match the web application user builder with the provided name
	 * 
	 * A web application user builder without a name doesn't match at all. A
	 * empty name matches any non empty builder name. Or the name must match the
	 * builder's name according {@link #match(String, String)}.
	 * 
	 * @param builder web application user builder
	 * @param name name
	 * @return {@code true}, if the builder and name matches, {@code false},
	 *         otherwise.
	 */
	private boolean match(WebAppUser.Builder builder, String name) {
		if (builder.name == null) {
			return false;
		}
		if (name.isEmpty()) {
			return !builder.name.isEmpty();
		} else {
			return match(builder.name, name);
		}
	}

	/**
	 * Add web application user.
	 * 
	 * If no S3 credentials are provided, the default S3 credentials are used,
	 * if available.
	 * 
	 * @param builder web application user builder
	 * @return {@code true}, if web application user have been added,
	 *         {@code false}, if web application user have been updated
	 */
	public boolean add(WebAppUser.Builder builder) {
		if (s3Default != null) {
			if (builder.accessKeyId == null && builder.accessKeySecret == null) {
				builder.accessKeyId = s3Default.accessKeyId;
				builder.accessKeySecret = s3Default.accessKeySecret;
			}
		}
		WebAppUser credentials = builder.build();
		return map.put(getKey(credentials.name), credentials) == null;
	}

	/**
	 * Add credentials.
	 * 
	 * @param credentials user credentials
	 * @return {@code true}, if user credentials have been added, {@code false},
	 *         if user credentials have been updated
	 */
	public boolean add(WebAppUser credentials) {
		if (s3Default != null) {
			if (credentials.accessKeyId == null && credentials.accessKeySecret == null) {
				WebAppUser.Builder builder = WebAppUser.builder();
				builder.name = credentials.name;
				builder.password = credentials.password;
				builder.accessKeyId = s3Default.accessKeyId;
				builder.accessKeySecret = s3Default.accessKeySecret;
				builder.webAppConfig = credentials.webAppConfig;
				builder.groups = credentials.groups;
				credentials = builder.build();
			}
		}
		return map.put(getKey(credentials.name), credentials) == null;
	}

	/**
	 * Get web application user.
	 * 
	 * @param name name of web application user
	 * @return web application user, {@code null}, if not available.
	 */
	public WebAppUser get(String name) {
		return map.get(getKey(name));
	}

	/**
	 * Remove web application user.
	 * 
	 * @param name name of web application user
	 * @return {@code true}, if web application user have been removed,
	 *         {@code false} otherwise.
	 */
	public boolean remove(String name) {
		return map.remove(getKey(name)) != null;
	}

	/**
	 * Number of entries.
	 * 
	 * @return number of entries
	 */
	public int size() {
		return map.size();
	}

	@Override
	public void save(Writer writer) throws IOException {
		if (s3Default != null) {
			writer.write(S3_POSTFIX + "=");
			writer.write(encode64(s3Default.accessKeyId));
			writer.write(',');
			writer.write(encode64(s3Default.accessKeySecret));
			writer.write(StringUtil.lineSeparator());
		}
		List<String> names = new ArrayList<>(map.keySet());
		names.sort(null);
		for (String name : names) {
			WebAppUser credentials = map.get(name);
			if (credentials != null) {
				writer.write(credentials.name);
				writer.write('=');
				writer.write(encode64(credentials.password));
				writer.write(StringUtil.lineSeparator());
				if (credentials.webAppConfig != null) {
					writer.write(credentials.name + CONFIG_POSTFIX);
					writer.write('=');
					writer.write(credentials.webAppConfig);
					writer.write(StringUtil.lineSeparator());
				}
				if (s3Default == null || !s3Default.accessKeyId.equals(credentials.accessKeyId)) {
					writer.write(credentials.name + S3_POSTFIX);
					writer.write('=');
					writer.write(encode64(credentials.accessKeyId));
					writer.write(',');
					writer.write(encode64(credentials.accessKeySecret));
					writer.write(StringUtil.lineSeparator());
				}
				if (credentials.groups != null && !credentials.groups.isEmpty()) {
					writer.write(credentials.name + GROUPS_POSTFIX);
					boolean first = true;
					for (String group : credentials.groups) {
						if (first) {
							writer.write('=');
							first = false;
						} else {
							writer.write(',');
						}
						writer.write(group);
					}
				}
			}
		}
	}

	@Override
	public int load(Reader reader) throws IOException {
		int entriesBefore = size();
		int entries = 0;
		BufferedReader lineReader = new BufferedReader(reader);
		try {
			int lineNumber = 0;
			int errors = 0;
			int comments = 0;
			WebAppUser.Builder builder = WebAppUser.builder();

			String line;
			// readLine() reads the secret into a String,
			// what may be considered to be a weak practice.
			while ((line = lineReader.readLine()) != null) {
				++lineNumber;
				try {
					if (!line.isEmpty() && !line.startsWith("#")) {
						String[] entry = line.split("=", 2);
						if (entry.length == 2) {
							String name = entry[0];
							String[] values = entry[1].split(",");
							if (name.equals("*" + S3_POSTFIX)) {
								WebAppUser.Builder def = WebAppUser.builder();
								def.name = "*";
								if (parseS3(def, "*", values)) {
									s3Default = def.build();
								} else {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								}
								continue;
							}
							String prefix = prefix(name, CONFIG_POSTFIX);
							if (prefix != name) {
								if (values.length != 1 || !match(builder, prefix)) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								} else {
									builder.webAppConfig = decodeText(values[0]);
								}
								continue;
							}
							prefix = prefix(name, S3_POSTFIX);
							if (prefix != name) {
								if (!parseS3(builder, prefix, values)) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								}
								continue;
							}
							prefix = prefix(name, GROUPS_POSTFIX);
							if (prefix != name) {
								if (!parseGroups(builder, prefix, values)) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								}
								continue;
							}
							prefix = prefix(name, PW_POSTFIX);
							if (prefix != name || isName(name)) {
								if (builder.name != null) {
									if (add(builder)) {
										++entries;
									}
									builder = WebAppUser.builder();
								}
								if (values.length != 1) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								} else {
									if (prefix == null) {
										builder.name = name;
									} else {
										builder.name = prefix;
									}
									builder.password = decodeTextOr64(values[0]);
								}
							}
						} else {
							++errors;
							LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
						}
					} else {
						++comments;
					}
				} catch (IllegalArgumentException ex) {
					++errors;
					LOGGER.warn("{}: '{}' invalid line!", lineNumber, line, ex);
				}
			}
			if (builder.name != null) {
				if (add(builder)) {
					++entries;
				}
			}
			if (size() == 0 && errors > 0 && lineNumber == comments + errors) {
				LOGGER.warn("read store, only errors, wrong password?");
				SecretUtil.destroy(this);
			}
		} catch (RuntimeException e) {
			LOGGER.warn("read store, unexpected error occurred!", e);
		} catch (IOException e) {
			if (e.getCause() instanceof GeneralSecurityException) {
				LOGGER.warn("read store, wrong password?", e);
				SecretUtil.destroy(this);
			} else {
				throw e;
			}
		} finally {
			try {
				lineReader.close();
			} catch (IOException e) {
			}
		}
		if (entriesBefore == 0) {
			LOGGER.info("read {} user credentials.", size());
		} else {
			LOGGER.info("read {} new user credentials (total {}).", entries, size());
		}
		return entries;
	}

	/**
	 * Parse S3 credentials.
	 * 
	 * The values must contain the S3 access key id in the first and the S3
	 * access key secret in the second value.
	 * 
	 * @param builder builder with web application user data
	 * @param name name part of line
	 * @param values split values of line
	 * @return {@code true} if the S3 credentials are valid, {@code false},
	 *         otherwise.
	 */
	private boolean parseS3(WebAppUser.Builder builder, String name, String[] values) {
		if (values.length != 2 || !match(builder, name)) {
			return false;
		}
		builder.accessKeyId = decodeTextOr64(values[0]);
		builder.accessKeySecret = decodeTextOr64(values[1]);
		return !builder.accessKeyId.isEmpty() && !builder.accessKeySecret.isEmpty();
	}

	/**
	 * Parse groups.
	 * 
	 * @param builder builder with web application user data
	 * @param name name part of line
	 * @param values split values of line
	 * @return {@code true} if the groups are valid, {@code false}, otherwise.
	 */
	private boolean parseGroups(WebAppUser.Builder builder, String name, String[] values) {
		if (!match(builder, name)) {
			return false;
		}
		for (int index = 0; index < values.length; ++index) {
			values[index] = decodeText(values[index]);
		}
		builder.groups = Arrays.asList(values);
		return true;
	}

	@Override
	public void destroy() throws DestroyFailedException {
		map.clear();
		destroyed = true;
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

	/**
	 * Encode UTF-8 text in base 64.
	 * 
	 * @param value UTF-8 text
	 * @return base 64
	 */
	private static String encode64(String value) {
		byte[] data = value.getBytes(StandardCharsets.UTF_8);
		return StringUtil.byteArrayToBase64(data);
	}

	/**
	 * Decode value to text.
	 * 
	 * A plain text value must be in single- ({@code '}) or double-quotes
	 * ({@code "}). Other values are considered to be base 64 encoded.
	 * 
	 * @param value value to be decoded
	 * @return text
	 */
	private static String decodeTextOr64(String value) {
		if (value.isEmpty()) {
			return value;
		}
		char c = value.charAt(0);
		if (value.length() > 2 && (c == '\'' || c == '"')) {
			int end = value.length() - 1;
			char e = value.charAt(end);
			if (e == c) {
				value = value.substring(1, end);
				return value;
			}
		}
		byte[] data = StringUtil.base64ToByteArray(value);
		return new String(data, StandardCharsets.UTF_8);
	}

	/**
	 * Decode text value.
	 * 
	 * If the value is in single- ({@code '}) or double-quotes ({@code "}),
	 * these are removed.
	 * 
	 * @param value value to be decoded
	 * @return text value
	 */
	private static String decodeText(String value) {
		if (!value.isEmpty()) {
			char c = value.charAt(0);
			if (value.length() > 2 && (c == '\'' || c == '"')) {
				int end = value.length() - 1;
				char e = value.charAt(end);
				if (e == c) {
					value = value.substring(1, end);
				}
			}
		}
		return value;
	}

	@Override
	public WebAppUserParser create() {
		return new WebAppUserParser(caseSensitiveNames);
	}

}
