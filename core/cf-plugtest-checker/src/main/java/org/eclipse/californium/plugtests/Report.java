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
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import java.util.ArrayList;
import java.util.List;

public class Report {

	private List<String> summary;
	
	public Report() {
		this.summary = new ArrayList<String>();
	}

	public List<String> getSummary() {
		return summary;
	}
	
	public void addEntry(String entry) {
		summary.add(entry);
	}
	
	public void print() {
		for (String entry:summary)
			System.out.println(entry);
	}
}
