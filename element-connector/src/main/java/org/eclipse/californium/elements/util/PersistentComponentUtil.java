/*******************************************************************************
 * Copyright (c) 2022 Bosch.IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.PersistentComponent;
import org.eclipse.californium.elements.PersistentComponentProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Save and load persistent components.
 * 
 * Currently only the dtls connections are persistent components.
 * 
 * In order to adjust timers based on uptime-nanoseconds,
 * {@link SerializationUtil#writeNanotimeSynchronizationMark(DatagramWriter)} is
 * used on saving, and
 * {@link SerializationUtil#readNanotimeSynchronizationMark(DataStreamReader)}
 * is used on reading. This preserves timers based on uptime, as long as the
 * {@link System#currentTimeMillis()} reflects a useful calendar time.
 * 
 * 
 * Note: the stream will contain not encrypted critical credentials. It is
 * required to protect this data before exporting it.
 * 
 * @since 3.4
 */
public class PersistentComponentUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(PersistentComponentUtil.class);
	/**
	 * Start mark for components in stream.
	 */
	private static final String MARK = "COMPONENTS";

	/**
	 * List of {@link PersistentComponentProvider}s.
	 * 
	 * @see #addProvider(PersistentComponentProvider)
	 * @see #removeProvider(PersistentComponentProvider)
	 */
	private final List<PersistentComponentProvider> providers = new ArrayList<>();

	/**
	 * Map of {@link PersistentComponent}s.
	 * 
	 * @see #add(PersistentComponent)
	 * @see #remove(PersistentComponent)
	 */
	private final ConcurrentMap<String, PersistentComponent> components = new ConcurrentHashMap<>();

	/**
	 * Map of {@link PersistentComponent}s including the provider's components
	 * to save and load.
	 * 
	 * @see #updateProvidersComponents()
	 */
	private final ConcurrentMap<String, PersistentComponent> all = new ConcurrentHashMap<>();

	/**
	 * Create persistent component utility.
	 */
	public PersistentComponentUtil() {

	}

	/**
	 * Update persistent components with current components of providers.
	 * 
	 * @see #addProvider(PersistentComponentProvider)
	 * @see #removeProvider(PersistentComponentProvider)
	 */
	public void updateProvidersComponents() {
		all.clear();
		all.putAll(components);
		for (PersistentComponentProvider provider : providers) {
			for (PersistentComponent component : provider.getComponents()) {
				all.put(component.getLabel(), component);
			}
		}
	}

	/**
	 * Add provider and all current components.
	 * 
	 * @param provider components provider
	 * @see #removeProvider(PersistentComponentProvider)
	 * @see #updateProvidersComponents()
	 */
	public void addProvider(PersistentComponentProvider provider) {
		providers.remove(provider);
		providers.add(provider);
		for (PersistentComponent component : provider.getComponents()) {
			all.put(component.getLabel(), component);
		}
	}

	/**
	 * Remove provider and all current components.
	 * 
	 * Note: if the provider has changed the returned components since it has
	 * been {@link #addProvider(PersistentComponentProvider)}ed, the state may
	 * be inconsistent. In that case use {@link #updateProvidersComponents()}
	 * before {@link #saveComponents(OutputStream, long)} or
	 * {@link #loadComponents(InputStream)}.
	 * 
	 * @param provider components provider
	 * @see #addProvider(PersistentComponentProvider)
	 * @see #updateProvidersComponents()
	 */
	public void removeProvider(PersistentComponentProvider provider) {
		providers.remove(provider);
		for (PersistentComponent component : provider.getComponents()) {
			all.remove(component.getLabel(), component);
		}
	}

	/**
	 * Add persistent component to serialization list.
	 * 
	 * @param component persistent component to serialization
	 * @see #remove(PersistentComponent)
	 * @see #loadComponents(InputStream)
	 * @see #saveComponents(OutputStream, long)
	 */
	public void add(PersistentComponent component) {
		components.put(component.getLabel(), component);
		all.put(component.getLabel(), component);
	}

	/**
	 * Remove persistent component to serialization list.
	 * 
	 * @param component persistent component to serialization
	 * @see #add(PersistentComponent)
	 * @see #loadComponents(InputStream)
	 * @see #saveComponents(OutputStream, long)
	 */
	public void remove(PersistentComponent component) {
		components.remove(component.getLabel(), component);
		all.remove(component.getLabel(), component);
	}

	/**
	 * Check, if persistent components are available.
	 * 
	 * @return {@code true}, if no persistent components is available,
	 *         {@code false}, if persistent components are available.
	 */
	public boolean isEmpty() {
		return all.isEmpty();
	}

	/**
	 * Load persistent components from input stream.
	 * 
	 * Starts with loading a time mark to update timers of components when
	 * loading them.
	 * 
	 * @param in input stream to read data from
	 * @return number of read items, {@code -1}, if start mark isn't found.
	 * @see #addProvider(PersistentComponentProvider)
	 * @see #add(PersistentComponent)
	 * @see #updateProvidersComponents()
	 * @see #load(InputStream, long)
	 */
	public int loadComponents(InputStream in) {
		long time = System.nanoTime();
		int count = 0;
		try {
			in.mark(32);
			DataStreamReader reader = new DataStreamReader(in);
			long delta = SerializationUtil.readNanotimeSynchronizationMark(reader);
			String mark = SerializationUtil.readString(reader, Byte.SIZE);
			if (!MARK.equals(mark)) {
				LOGGER.info("Mismatch, {} != {}", MARK, mark);
				in.reset();
				return -1;
			}
			count = load(in, delta);
		} catch (IllegalArgumentException e) {
			LOGGER.warn("loading failed:", e);
		} catch (IOException e) {
			LOGGER.warn("loading failed:", e);
		}
		time = System.nanoTime() - time;
		LOGGER.info("load: {} ms, {} items", TimeUnit.NANOSECONDS.toMillis(time), count);
		return count;
	}

	/**
	 * Save all added persistent components to output stream.
	 * 
	 * Starts with saving a time mark in order to adjust timers of components
	 * when loading them.
	 * 
	 * Note: the stream will contain not encrypted critical credentials. It is
	 * required to protect this data before exporting it.
	 * 
	 * @param out output stream to write data to
	 * @param staleThresholdInSeconds stale threshold in seconds. e.g.
	 *            Connections without traffic for that time are skipped during
	 *            serialization.
	 * @return number of written items
	 * @throws IOException if an i/o-error occurred
	 * @see #add(PersistentComponent)
	 * @see #addProvider(PersistentComponentProvider)
	 * @see #updateProvidersComponents()
	 * @see #save(OutputStream, long)
	 */
	public int saveComponents(OutputStream out, long staleThresholdInSeconds) throws IOException {
		long start = System.nanoTime();
		DatagramWriter writer = new DatagramWriter();
		SerializationUtil.writeNanotimeSynchronizationMark(writer);
		SerializationUtil.write(writer, MARK, Byte.SIZE);
		writer.writeTo(out);
		int count = save(out, staleThresholdInSeconds);
		long time = System.nanoTime() - start;
		LOGGER.info("save: {} ms, {} connections", TimeUnit.NANOSECONDS.toMillis(time), count);
		return count;
	}

	/**
	 * Load persistent components from input stream.
	 * 
	 * @param in input stream to read data from
	 * @param deltaNanos adjust-delta for nano-uptime in nanoseconds. If the
	 *            stream contains timestamps based on nano-uptime, this delta
	 *            should be applied on order to adjust these timestamps
	 *            according the current nano uptime and the passed real time.
	 * @return number of read items
	 * @see #add(PersistentComponent)
	 */
	public int load(InputStream in, long deltaNanos) {
		int count = 0;
		List<String> failed = new ArrayList<>();
		try {
			String label;
			while ((label = SerializationUtil.readString(new DataStreamReader(in), Short.SIZE)) != null) {
				PersistentComponent component = all.get(label);
				if (component != null) {
					int loaded = component.load(in, deltaNanos);
					LOGGER.info("loading {}, {} items, {} components.", label, loaded, all.size());
					count += loaded;
				} else {
					int skip = SerializationUtil.skipItems(new DataStreamReader(in), Short.SIZE);
					LOGGER.warn("loading {} failed, {} items skipped, no component found!", label, skip);
					failed.add(label);
				}
			}
		} catch (IllegalArgumentException e) {
			LOGGER.warn("loading failed:", e);
		} catch (IOException e) {
			LOGGER.warn("loading failed:", e);
		}
		if (!failed.isEmpty()) {
			LOGGER.warn("Loading failures:");
			int index = 0;
			for (String label : failed) {
				LOGGER.warn("[LOAD {}] {}", index++, label);
			}
			index = 0;
			for (String label : all.keySet()) {
				LOGGER.warn("[COMP {}] {}", index++, label);
			}
		}
		return count;
	}

	/**
	 * Save all added persistent components to output stream.
	 * 
	 * Note: the stream will contain not encrypted critical credentials. It is
	 * required to protect this data before exporting it.
	 * 
	 * @param out output stream to write data to
	 * @param staleThresholdInSeconds stale threshold in seconds. e.g.
	 *            Connections without traffic for that time are skipped during
	 *            serialization.
	 * @return number of written items
	 * @throws IOException if an i/o-error occurred
	 * @see #add(PersistentComponent)
	 */
	public int save(OutputStream out, long staleThresholdInSeconds) throws IOException {
		int count = 0;
		DatagramWriter writer = new DatagramWriter();
		for (PersistentComponent component : all.values()) {
			String label = component.getLabel();
			SerializationUtil.write(writer, label, Short.SIZE);
			writer.writeTo(out);
			int saved = component.save(out, staleThresholdInSeconds);
			LOGGER.info("saved: {} items of {}", saved, label);
			count += saved;
		}
		SerializationUtil.write(writer, (String) null, Short.SIZE);
		writer.writeTo(out);
		return count;
	}

}
