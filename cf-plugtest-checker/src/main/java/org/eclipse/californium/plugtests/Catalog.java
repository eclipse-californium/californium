/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;

import org.reflections.Reflections;

import org.eclipse.californium.plugtests.PlugtestChecker.TestClientAbstract;

/**
 * A catalog with all tests
 */
public class Catalog {
	
	public static final Class<?> PLUGTEST_2_SUPERCLASS = TestClientAbstract.class;
	
	private HashMap<String, Class<?>> catalog;
	
	public Catalog() {
		this.catalog = new HashMap<String, Class<?>>();
		loadSubclasses(PLUGTEST_2_SUPERCLASS);
	}
	
	public void loadSubclasses(Class<?> superclass) {
		Reflections reflections = new Reflections("org.eclipse.californium");
		for (Class<?> clazz:reflections.getSubTypesOf(superclass))
			loadClass(clazz);
	}
	
	public void loadClass(Class<?> clazz) {
		catalog.put(clazz.getSimpleName(), clazz);
	}
	
	public Class<?> getTestClass(String name) {
		return catalog.get(name);
	}
	
	public List<Class<?>> getTestsClasses(String... names) {
		if (names.length==0) names = new String[] {".*"};
		
		List<Class<?>> list = new ArrayList<Class<?>>();
		for (Entry<String, Class<?>> entry:catalog.entrySet()) {
			for (String name:names) {
				String regex = name.replace("*", ".*");
				if (entry.getKey().matches(regex))
					list.add(entry.getValue());
			}
		}
		return list;
	}
	
	public List<String> getAllTestNames() {
		ArrayList<String> list = new ArrayList<String>(catalog.keySet());
		Collections.sort(list);
		return list;
	}
}
