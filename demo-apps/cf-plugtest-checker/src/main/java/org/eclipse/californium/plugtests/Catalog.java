/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Achim Kraus (Bosch Software Innovations GmbH) - sort resulting test class list
 *                                                    don't load inner test classes
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import java.io.File;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * A catalog with all tests
 */
public class Catalog {

	private static final String PACKAGE = "org.eclipse.californium.plugtests.tests";

	private HashMap<String, Class<?>> catalog;

	public Catalog() {
		this.catalog = new HashMap<String, Class<?>>();
		try {
			loadSubclasses();
		} catch (Exception e) {
			System.err.println("Reflection error.");
			e.printStackTrace();
			return;
		}
	}

	public void loadSubclasses() throws Exception {

		ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
		String packageName = PACKAGE.replace(".", "/");
		URL packageURL = classLoader.getResource(packageName);

		if (packageURL.getProtocol().equals("jar")) {

			String jarFileName = URLDecoder.decode(packageURL.getFile(), "UTF-8");
			jarFileName = jarFileName.substring(5, jarFileName.indexOf("!"));

			JarFile jar = new JarFile(jarFileName);
			Enumeration<JarEntry> jarEntries = jar.entries();

			while (jarEntries.hasMoreElements()) {
				String clazz = jarEntries.nextElement().getName();
				if (clazz.startsWith(packageName) && clazz.length() > packageName.length() + 5) {
					clazz = clazz.substring(0, clazz.length()-6); // remove ".class"
					clazz = clazz.replace("/", "."); // convert to canonical name
					loadClass(Class.forName(clazz));
				}
			}

			jar.close();

		} else {
			URI uri = new URI(packageURL.toString());

			File folder = new File(uri.getPath());
			File[] content = folder.listFiles();

			for (File file : content) {
				String clazz = file.getName().substring(0, file.getName().length()-6); // remove ".class"
				loadClass(Class.forName(PACKAGE + "." + clazz));
			}
		}
	}

	public void loadClass(Class<?> clazz) {
		// don't load inner classes
		if (!clazz.getSimpleName().isEmpty()) {
			catalog.put(clazz.getSimpleName(), clazz);
		}
	}

	public Class<?> getTestClass(String name) {
		return catalog.get(name);
	}

	public List<Class<?>> getTestsClasses(String... names) {
		if (names.length == 0) {
			names = new String[] { ".*" };
		} else {
			String[] regexs = new String[names.length];
			for (int index = 0; index < names.length; ++index) {
				regexs[index] = names[index].replace("*", ".*");
			}
			names = regexs;
		}

		List<Class<?>> list = new ArrayList<Class<?>>();
		for (Entry<String, Class<?>> entry : catalog.entrySet()) {
			for (String regex : names) {
				if (entry.getKey().matches(regex)) {
					list.add(entry.getValue());
				}
			}
		}
		Collections.sort(list, new Comparator<Class<?>>() {

			@Override
			public int compare(Class<?> o1, Class<?> o2) {
				return o1.getSimpleName().compareTo(o2.getSimpleName());
			}
		});
		return list;
	}

	public List<String> getAllTestNames() {
		ArrayList<String> list = new ArrayList<String>(catalog.keySet());
		Collections.sort(list);
		return list;
	}
}
