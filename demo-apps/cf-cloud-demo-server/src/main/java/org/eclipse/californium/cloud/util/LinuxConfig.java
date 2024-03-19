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
package org.eclipse.californium.cloud.util;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.elements.util.EncryptedStreamUtil;
import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.SystemResourceMonitors.FileMonitor;
import org.eclipse.californium.elements.util.SystemResourceMonitors.SystemResourceCheckReady;
import org.eclipse.californium.elements.util.SystemResourceMonitors.SystemResourceMonitor;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Linux style configuration.
 * 
 * @since 3.11
 */
public class LinuxConfig implements Destroyable {

	private static final Logger LOGGER = LoggerFactory.getLogger(LinuxConfig.class);

	private static final String DEFAULT_SECTION = "default";

	/**
	 * Configuration map.
	 */
	private static class ConfigMap implements Destroyable {

		private static final Pattern SECTION = Pattern.compile("^\\s*\\[([^\\]]+)\\]\\s*$");

		/**
		 * Map of sections and configurations.
		 */
		private final ConcurrentMap<String, Map<String, String>> map = new ConcurrentHashMap<>();
		/**
		 * {@code true} to use case sensitive sections, {@code false},
		 * otherwise.
		 */
		private final boolean caseSensitiveSections;
		/**
		 * {@code true} to use case sensitive names, {@code false}, otherwise.
		 */
		private final boolean caseSensitiveNames;
		/**
		 * {@code true} if credentials are destroyed.
		 */
		private volatile boolean destroyed;

		/**
		 * Create configurations map.
		 * 
		 * @param caseSensitiveSections {@code true} to use case sensitive
		 *            sections, {@code false}, otherwise.
		 * @param caseSensitiveNames {@code true} to use case sensitive names,
		 *            {@code false}, otherwise.
		 */
		private ConfigMap(boolean caseSensitiveSections, boolean caseSensitiveNames) {
			this.caseSensitiveSections = caseSensitiveSections;
			this.caseSensitiveNames = caseSensitiveNames;
		}

		private String getSectionKey(String section) {
			String key = section;
			if (!caseSensitiveSections) {
				key = key.toLowerCase();
			}
			return key;
		}

		private String getNameKey(String name) {
			String key = name;
			if (!caseSensitiveNames) {
				key = key.toLowerCase();
			}
			return key;
		}

		/**
		 * Get sub-sections.
		 * 
		 * @param section section name
		 * @return map of sub-sections
		 */
		private Map<String, Map<String, String>> getSubSections(String section) {
			String key = getSectionKey(section);
			if (!key.endsWith(".")) {
				key += ".";
			}
			Map<String, Map<String, String>> subsections = new HashMap<>();
			for (Map.Entry<String, Map<String, String>> entry : map.entrySet()) {
				if (entry.getKey().startsWith(key)) {
					String k = entry.getKey().substring(key.length());
					subsections.put(k, entry.getValue());
				}
			}
			return subsections;
		}

		/**
		 * Get configuration section.
		 * 
		 * @param section section of configuration
		 * @return configuration section, {@code null}, if not available.
		 */
		private Map<String, String> get(String section) {
			return map.get(getSectionKey(section));
		}

		/**
		 * Get configuration value.
		 * 
		 * @param section section name
		 * @param name field name
		 * @return configuration value, {@code null}, if not available.
		 */
		private String get(String section, String name) {
			String value = null;
			Map<String, String> sectionMap = get(section);
			if (sectionMap != null) {
				value = sectionMap.get(getNameKey(name));
			}
			return value;
		}

		/**
		 * Number of entries.
		 * 
		 * @return number of entries
		 */
		private int size() {
			return map.size();
		}

		/**
		 * Lines in format:
		 * 
		 * <pre>
		 * [section]
		 * name1 = valueA
		 * name2 = valueB
		 * </pre>
		 * 
		 * @param writer writer to save configuration
		 * @throws IOException if an I/O error occurred
		 */
		private void save(Writer writer) throws IOException {
			List<String> sections = new ArrayList<>(map.keySet());
			Collections.sort(sections);
			for (String section : sections) {
				writer.write('[');
				writer.write(section);
				writer.write(']');
				writer.write(StringUtil.lineSeparator());
				Map<String, String> sectionMap = map.get(section);
				if (sectionMap != null) {
					List<String> names = new ArrayList<>(sectionMap.keySet());
					Collections.sort(names);
					for (String name : names) {
						writer.write(name);
						String value = sectionMap.get(name);
						if (value != null) {
							writer.write(" = ");
							writer.write(value);
						}
						writer.write(StringUtil.lineSeparator());
					}
				}
			}
		}

		/**
		 * Load configuration.
		 * 
		 * <pre>
		 * [section]
		 * name1 = valueA
		 * name2 = valueB
		 * </pre>
		 * 
		 * @param reader reader for configuration.
		 * @throws IOException if an I/O error occurred
		 */
		private void load(Reader reader) throws IOException {
			int values = 0;
			BufferedReader lineReader = new BufferedReader(reader);
			try {
				int lineNumber = 0;
				int errors = 0;
				int comments = 0;
				String line;
				Map<String, String> sectionMap = null;
				String section = null;
				while ((line = lineReader.readLine()) != null) {
					++lineNumber;
					try {
						if (!line.isEmpty() && !line.startsWith("#")) {
							Matcher matcher = SECTION.matcher(line);
							if (matcher.matches()) {
								section = getSectionKey(matcher.group(1));
								sectionMap = map.putIfAbsent(section, new ConcurrentHashMap<String, String>());
								if (sectionMap == null) {
									sectionMap = map.get(section);
								}
							} else {
								if (sectionMap != null) {
									String[] entry = line.split("=", 2);
									String name = getNameKey(entry[0].trim());
									String value = "";
									if (entry.length == 2) {
										value = entry[1].trim();
									}
									sectionMap.put(name, value);
									++values;
								} else {
									++errors;
									LOGGER.warn("{}: '{}' missing scope!", lineNumber, line);
								}
							}
						} else {
							++comments;
						}
					} catch (IllegalArgumentException ex) {
						++errors;
						LOGGER.warn("{}: '{}' invalid line!", lineNumber, line, ex);
					}
				}
				if (size() == 0 && errors > 0 && lineNumber == comments + errors) {
					LOGGER.warn("read store, only errors, wrong password?");
					SecretUtil.destroy(this);
					values = 0;
				}
			} catch (

			IOException e) {
				if (e.getCause() instanceof GeneralSecurityException) {
					LOGGER.warn("read store, wrong password?", e);
					SecretUtil.destroy(this);
					values = 0;
				} else {
					throw e;
				}
			} finally {
				try {
					lineReader.close();
				} catch (IOException e) {
				}
			}
			LOGGER.info("read {} scopes, {} values.", size(), values);
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
	}

	/**
	 * Encryption utility for encrypted configuration.
	 */
	private final EncryptedStreamUtil encryptionUtility = new EncryptedStreamUtil();
	/**
	 * {@code true} to use case sensitive sections, {@code false}, otherwise.
	 */
	private final boolean caseSensitiveSections;
	/**
	 * {@code true} to use case sensitive names, {@code false}, otherwise.
	 */
	private final boolean caseSensitiveNames;
	/**
	 * Map of sections of configurations.
	 */
	private volatile ConfigMap configurations;
	/**
	 * {@code true} if user store is destroyed.
	 */
	private volatile boolean destroyed;

	/**
	 * Seed of last loaded file.
	 * 
	 * The seed is a random header to ensure, that the encrypted file will be
	 * different, even if the same credentials are contained. Used to detect
	 * changes in encrypted file.
	 * 
	 * @see #clearSeed()
	 * @see #loadLinuxConfig(String, SecretKey)
	 * @see #loadLinuxConfig(InputStream, SecretKey)
	 */
	private byte[] seed;

	/**
	 * Create user file store.
	 * 
	 * @param caseSensitiveSections {@code true} to use case sensitive sections,
	 *            {@code false}, otherwise.
	 * @param caseSensitiveNames {@code true} to use case sensitive names,
	 *            {@code false}, otherwise.
	 */
	public LinuxConfig(boolean caseSensitiveSections, boolean caseSensitiveNames) {
		this.caseSensitiveSections = caseSensitiveSections;
		this.caseSensitiveNames = caseSensitiveNames;
		this.configurations = new ConfigMap(caseSensitiveSections, caseSensitiveNames);
	}

	/**
	 * 
	 * Get write cipher specification.
	 * 
	 * @return cipher specification (algorithm + key size). e.g. "AES/GCM/128".
	 */
	public String getWriteCipher() {
		return encryptionUtility.getWriteCipher();
	}

	/**
	 * Get read cipher specification.
	 * 
	 * @return cipher specification (algorithm + key size). e.g. "AES/GCM/128".
	 *         {@code null}, if
	 */
	public String getReadCipher() {
		return encryptionUtility.getReadCipher();
	}

	/**
	 * Set cipher to default cipher.
	 * 
	 * @see EncryptedStreamUtil#setDefaultWriteCipher()
	 */
	public void setDefaultWriteCipher() {
		encryptionUtility.setDefaultWriteCipher();
	}

	/**
	 * Set algorithm and key size.
	 * 
	 * @param cipherAlgorithm cipher algorithm
	 * @param keySizeBits key size in bits
	 * @throws IllegalArgumentException if cipher and key size is not supported
	 */
	public void setWriteCipher(String cipherAlgorithm, int keySizeBits) {
		encryptionUtility.setWriteCipher(cipherAlgorithm, keySizeBits);
	}

	/**
	 * Set algorithm and key size.
	 * 
	 * @param spec cipher specification (algorithm + key size). e.g.
	 *            "AES/GCM/128".
	 * @throws IllegalArgumentException if cipher and key size is not supported
	 */
	public void setWriteCipher(String spec) {
		encryptionUtility.setWriteCipher(spec);
	}

	/**
	 * Get resource monitor for automatic configuration reloading.
	 * 
	 * @param file filename of configuration.
	 * @param password password of configuration. {@code null} to use
	 *            {@link #loadLinuxConfig(String)} instead of
	 *            {@link #loadLinuxConfig(String, SecretKey)}.
	 * @return resource monitor
	 */
	public SystemResourceMonitor getMonitor(final String file, final SecretKey password) {

		return new FileMonitor(file) {

			private SecretKey monitorPassword = SecretUtil.create(password);

			@Override
			protected void update(MonitoredValues values, SystemResourceCheckReady ready) {
				if (file != null) {
					if (monitorPassword != null) {
						loadLinuxConfig(file, monitorPassword);
					} else {
						loadLinuxConfig(file);
					}
				}
				ready(values);
				ready.ready(false);
			}
		};
	}

	/**
	 * Clear seed to force loading.
	 * 
	 * The store keeps the "seed" of encrypted files in order to prevent
	 * reloading that same file. To force loading the file, clear the "seed".
	 * 
	 * @see #loadLinuxConfig(String, SecretKey)
	 * @see #loadLinuxConfig(InputStream, SecretKey)
	 */
	public void clearSeed() {
		this.seed = null;
	}

	/**
	 * Load configuration.
	 * 
	 * @param file filename of configuration.
	 * @return the linux configuration for chaining
	 * @see #loadLinuxConfig(Reader)
	 */
	public LinuxConfig loadLinuxConfig(String file) {
		try (InputStream in = new FileInputStream(file)) {
			try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
				loadLinuxConfig(reader);
			}
		} catch (IOException e) {
			LOGGER.warn("read config:", e);
		}
		return this;
	}

	/**
	 * Load configuration.
	 * 
	 * @param in input stream.
	 * @return the linux configuration for chaining
	 * @see #loadLinuxConfig(Reader)
	 */
	public LinuxConfig loadLinuxConfig(InputStream in) {
		try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
			loadLinuxConfig(reader);
		} catch (IOException e) {
			LOGGER.warn("read config:", e);
		}
		return this;
	}

	/**
	 * Load encrypted configuration.
	 * 
	 * @param file filename of configuration.
	 * @param password password of configuration.
	 * @return the linux configuration for chaining
	 * @see #loadLinuxConfig(Reader)
	 */
	public LinuxConfig loadLinuxConfig(String file, SecretKey password) {
		try (InputStream in = new FileInputStream(file)) {
			loadLinuxConfig(in, password);
		} catch (IOException e) {
			LOGGER.warn("read config:", e);
		}
		return this;
	}

	/**
	 * Load encrypted configuration.
	 * 
	 * @param in input stream of configuration.
	 * @param password password of configuration.
	 * @return the linux configuration for chaining
	 * @see #loadLinuxConfig(Reader)
	 */
	public LinuxConfig loadLinuxConfig(InputStream in, SecretKey password) {
		byte[] seed = encryptionUtility.readSeed(in);
		if (this.seed == null && !Arrays.equals(this.seed, seed)) {
			try (InputStream inEncrypted = encryptionUtility.prepare(seed, in, password)) {
				loadLinuxConfig(inEncrypted);
				this.seed = seed;
			} catch (IOException e) {
				LOGGER.warn("read config:", e);
			}
		} else {
			LOGGER.debug("Encrypted config not changed, (same seed).");
		}
		return this;
	}

	/**
	 * Load configuration.
	 * 
	 * Lines in format:
	 * 
	 * <pre>
	 * [section]
	 * name1 = valueA
	 * name2 = valueB
	 * </pre>
	 * 
	 * @param reader reader for configuration.
	 * @return the linux configuration for chaining
	 * @throws IOException if an I/O error occurred Load encrypted
	 *             configuration.
	 */
	public LinuxConfig loadLinuxConfig(Reader reader) throws IOException {
		ConfigMap newConfigurations = new ConfigMap(caseSensitiveSections, caseSensitiveNames);
		newConfigurations.load(reader);
		if (newConfigurations.isDestroyed()) {
			if (configurations.size() == 0) {
				destroyed = true;
			}
		} else {
			configurations = newConfigurations;
			this.seed = null;
		}
		return this;
	}

	/**
	 * Save configuration.
	 * 
	 * @param file filename of configuration.
	 * @return the linux configuration for chaining
	 * @see #saveLinuxConfig(Writer)
	 */
	public LinuxConfig saveLinuxConfig(String file) {
		try (OutputStream out = new FileOutputStream(file)) {
			try (Writer writer = new OutputStreamWriter(out, StandardCharsets.UTF_8)) {
				saveLinuxConfig(writer);
			}
		} catch (IOException e) {
			LOGGER.warn("write config:", e);
		}
		return this;
	}

	/**
	 * Save configuration.
	 * 
	 * @param out output stream.
	 * @return the linux configuration for chaining
	 * @see #saveLinuxConfig(Writer)
	 */
	public LinuxConfig saveLinuxConfig(OutputStream out) {
		try (Writer writer = new OutputStreamWriter(out, StandardCharsets.UTF_8)) {
			saveLinuxConfig(writer);
		} catch (IOException e) {
			LOGGER.warn("write config:", e);
		}
		return this;
	}

	/**
	 * Save encrypted configuration.
	 * 
	 * @param file filename of configuration.
	 * @param password password of configuration.
	 * @return the linux configuration for chaining
	 * @see #saveLinuxConfig(Writer)
	 */
	public LinuxConfig saveLinuxConfig(String file, SecretKey password) {
		try (OutputStream out = new FileOutputStream(file)) {
			saveLinuxConfig(out, password);
		} catch (IOException e) {
			LOGGER.warn("write config:", e);
		}
		return this;
	}

	/**
	 * Save encrypted configuration.
	 * 
	 * @param out output stream to save configuration.
	 * @param password password of configuration.
	 * @return the linux configuration for chaining
	 * @see #saveLinuxConfig(Writer)
	 */
	public LinuxConfig saveLinuxConfig(OutputStream out, SecretKey password) {
		try (OutputStream outEncrypted = encryptionUtility.prepare(seed, out, password)) {
			saveLinuxConfig(outEncrypted);
		} catch (IOException e) {
			LOGGER.warn("write config:", e);
		}
		return this;
	}

	/**
	 * Save configuration.
	 * 
	 * Lines in format:
	 * 
	 * <pre>
	 * [section]
	 * name1 = valueA
	 * name2 = valueB
	 * </pre>
	 * 
	 * @param writer writer to save configuration.
	 * @return the linux configuration for chaining
	 * @throws IOException if an I/O error occurred
	 */
	public LinuxConfig saveLinuxConfig(Writer writer) throws IOException {
		configurations.save(writer);
		return this;
	}

	public boolean hasSection(String section) {
		return configurations.get(section) != null;
	}

	/**
	 * Get values of section.
	 * 
	 * @param section section name
	 * @return map of section values
	 */
	public Map<String, String> getValues(String section) {
		return configurations.get(section);
	}

	/**
	 * Get sub-sections.
	 * 
	 * @param section section name
	 * @return map of sub-sections
	 */
	public Map<String, Map<String, String>> getSubSections(String section) {
		return configurations.getSubSections(section);
	}

	/**
	 * Get field value of {@code "default"} section.
	 * 
	 * @param name field name
	 * @return field value
	 */
	public String get(String name) {
		return getWithDefault(DEFAULT_SECTION, name, null);
	}

	/**
	 * Get field value.
	 * 
	 * @param section section name
	 * @param name field name
	 * @return field value
	 */
	public String get(String section, String name) {
		return getWithDefault(section, name, null);
	}

	/**
	 * Get value with default of {@code "default"} section.
	 * 
	 * @param name field name
	 * @param def default value
	 * @return value, or, if not available, the provided default value
	 */
	public String getWithDefault(String name, String def) {
		return getWithDefault(DEFAULT_SECTION, name, def);
	}

	/**
	 * Get value with default.
	 * 
	 * @param section section name
	 * @param name field name
	 * @param def default value
	 * @return value, or, if not available, the provided default value
	 */
	public String getWithDefault(String section, String name, String def) {
		String value = configurations.get(section, name);
		if (value == null) {
			value = def;
		}
		return value;
	}

	/**
	 * Size.
	 * 
	 * @return number of sections.
	 */
	public int size() {
		return configurations.size();
	}

	@Override
	public void destroy() throws DestroyFailedException {
		configurations.destroy();
		destroyed = true;
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

}
