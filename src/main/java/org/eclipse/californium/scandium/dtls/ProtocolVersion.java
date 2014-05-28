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
 *    Stefan Jucker - DTLS implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * Represents the protocol version.
 */
public class ProtocolVersion implements Comparable<ProtocolVersion> {
	
	/** The minor. */
	private int minor;
	
	/** The major. */
	private int major;
	
	/**
	 * The latest version supported.
	 */
	public ProtocolVersion() {
		this.major = 254;
		this.minor = 253;
	}

	/**
	 * Instantiates a new protocol version.
	 *
	
	 * @param major the major
	 * @param minor the minor
	 */
	public ProtocolVersion(int major, int minor) {
		this.minor = minor;
		this.major = major;
	}
	
	public int getMinor() {
		return minor;
	}

	public int getMajor() {
		return major;
	}

	//@Override
	public int compareTo(ProtocolVersion o) {
		/*
		 * Example, version 1.0 (254,255) is smaller than version 1.2 (254,253)
		 */
		
		if (major == o.getMajor()) {
			if (minor < o.getMinor()) {
				return 1;
			} else if (minor > o.getMinor()) {
				return -1;
			} else {
				return 0;
			}
		} else if (major < o.getMajor()) {
			return 1;
		} else {
			return -1;
		}
	}
	
	
}
