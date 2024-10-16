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
package org.eclipse.californium.cloud.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.DestroyFailedException;

import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Linux style configuration.
 * 
 * @since 3.12
 */
public class LinuxConfigParser implements ResourceParser<LinuxConfigParser> {

	private static final Logger LOGGER = LoggerFactory.getLogger(LinuxConfigParser.class);

	public static final String DEFAULT_SECTION = "default";

	private static final Pattern SECTION = Pattern.compile("^\\s*\\[([^\\]]+)\\]\\s*$");

	/**
	 * Map of sections and configurations.
	 */
	private final ConcurrentMap<String, Map<String, String>> map = new ConcurrentHashMap<>();
	/**
	 * {@code true} to use case sensitive sections, {@code false}, otherwise.
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
	 * @param caseSensitiveSections {@code true} to use case sensitive sections,
	 *            {@code false}, otherwise.
	 * @param caseSensitiveNames {@code true} to use case sensitive names,
	 *            {@code false}, otherwise.
	 */
	public LinuxConfigParser(boolean caseSensitiveSections, boolean caseSensitiveNames) {
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
	public Map<String, Map<String, String>> getSubSections(String section) {
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
	@Override
	public void save(Writer writer) throws IOException {
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
	 * @return number of added entries.
	 * @throws IOException if an I/O error occurred
	 */
	@Override
	public int load(Reader reader) throws IOException {
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
		} catch (RuntimeException e) {
			LOGGER.warn("read store, unexpected error occurred!", e);
		} catch (IOException e) {
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
		return values;
	}

	@Override
	public LinuxConfigParser create() {
		return new LinuxConfigParser(caseSensitiveSections, caseSensitiveNames);
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
	 * Number of entries.
	 * 
	 * @return number of entries
	 */
	public int size() {
		return map.size();
	}

	public boolean hasSection(String section) {
		return map.containsKey(getSectionKey(section));
	}

	/**
	 * Get sections.
	 * 
	 * @return set of sections
	 */
	public Set<String> getSections() {
		return map.keySet();
	}

	/**
	 * Get values of section.
	 * 
	 * @param section section name
	 * @return map of section values
	 */
	public Map<String, String> getValues(String section) {
		return map.get(getSectionKey(section));
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
	 * Remove field from {@code "default"} section.
	 * 
	 * @param name field name
	 * @return removed field value, {@code null}, if field wasn't available.
	 * @since 4.0
	 */
	public String remove(String name) {
		return remove(DEFAULT_SECTION, name);
	}

	/**
	 * Remove field.
	 * 
	 * @param section section name
	 * @param name field name
	 * @return removed field value, {@code null}, if field wasn't available.
	 * @since 4.0
	 */
	public String remove(String section, String name) {
		String value = null;
		Map<String, String> sectionMap = getValues(section);
		if (sectionMap != null) {
			value = sectionMap.remove(getNameKey(name));
		}
		return value;
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
		String value = null;
		Map<String, String> sectionMap = getValues(section);
		if (sectionMap != null) {
			value = sectionMap.get(getNameKey(name));
		}
		if (value == null) {
			value = def;
		}
		return value;
	}

	/**
	 * Get field value.
	 * 
	 * @param name field name
	 * @return field value
	 */
	public Boolean getBoolean(String name) {
		return getBoolean(DEFAULT_SECTION, name, null);
	}

	/**
	 * Get field value.
	 * 
	 * @param name field name
	 * @param def default value
	 * @return field value
	 */
	public Boolean getBoolean(String name, Boolean def) {
		return getBoolean(DEFAULT_SECTION, name, def);
	}

	/**
	 * Get field value.
	 * 
	 * @param section section name
	 * @param name field name
	 * @return field value
	 */
	public Boolean getBoolean(String section, String name) {
		return getBoolean(section, name, null);
	}

	/**
	 * Get field value.
	 * 
	 * @param section section name
	 * @param name field name
	 * @param def default value
	 * @return field value
	 */
	public Boolean getBoolean(String section, String name, Boolean def) {
		String value = get(section, name);
		if (value != null) {
			return Boolean.parseBoolean(value);
		} else {
			return def;
		}
	}

	/**
	 * Get field value.
	 * 
	 * @param name field name
	 * @return field value
	 */
	public Long getLong(String name) {
		return getLong(DEFAULT_SECTION, name, null);
	}

	/**
	 * Get field value.
	 * 
	 * @param name field name
	 * @param def default value
	 * @return field value
	 */
	public Long getLong(String name, Long def) {
		return getLong(DEFAULT_SECTION, name, def);
	}

	/**
	 * Get field value.
	 * 
	 * @param section section name
	 * @param name field name
	 * @return field value
	 */
	public Long getLong(String section, String name) {
		return getLong(section, name, null);
	}

	/**
	 * Get field value.
	 * 
	 * @param section section name
	 * @param name field name
	 * @param def default value
	 * @return field value
	 */
	public Long getLong(String section, String name, Long def) {
		String value = get(section, name);
		if (value != null) {
			try {
				return Long.parseLong(value);
			} catch (NumberFormatException ex) {
				if (def != null) {
					LOGGER.warn("{} is no long! Replaced by {}.", value, def);
				} else {
					LOGGER.warn("{} is no long!", value);
				}
			}
		}
		return def;
	}

	/**
	 * Get field value.
	 * 
	 * @param name field name
	 * @return field value
	 */
	public Integer getInteger(String name) {
		return getInteger(DEFAULT_SECTION, name, null);
	}

	/**
	 * Get field value.
	 * 
	 * @param name field name
	 * @param def default value
	 * @return field value
	 */
	public Integer getInteger(String name, Integer def) {
		return getInteger(DEFAULT_SECTION, name, def);
	}

	/**
	 * Get field value.
	 * 
	 * @param section section name
	 * @param name field name
	 * @return field value
	 */
	public Integer getInteger(String section, String name) {
		return getInteger(section, name, null);
	}

	/**
	 * Get field value.
	 * 
	 * @param section section name
	 * @param name field name
	 * @param def default value
	 * @return field value
	 */
	public Integer getInteger(String section, String name, Integer def) {
		String value = get(section, name);
		if (value != null) {
			try {
				return Integer.parseInt(value);
			} catch (NumberFormatException ex) {
				if (def != null) {
					LOGGER.warn("{} is no long! Replaced by {}.", value, def);
				} else {
					LOGGER.warn("{} is no long!", value);
				}
			}
		}
		return def;
	}

}
