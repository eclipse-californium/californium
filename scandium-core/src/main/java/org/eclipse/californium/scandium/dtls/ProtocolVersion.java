/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla - documentation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * Represents the DTLS protocol version.
 * 
 * Note that the major and minor version numbers are represented as the 1's
 * complement of the corresponding DTLS version numbers, e.g. DTLS version 1.2
 * is represented as bytes {254, 253}.
 * 
 * See <a href="http://tools.ietf.org/html/rfc6347#section-4.1"> Datagram
 * Transport Layer Security Version 1.2 (RFC 6347), Section 4.1</a> for details.
 */
public class ProtocolVersion implements Comparable<ProtocolVersion> {

	/**
	 * Major version for DTLS 1.x.
	 * 
	 * @since 2.5
	 */
	public static final int MAJOR_1 = 254;

	/**
	 * Minor version for DTLS x.2.
	 * 
	 * @since 2.5
	 */
	public static final int MINOR_2 = 253;

	/**
	 * Minor version for DTLS x.0.
	 * 
	 * @since 2.5
	 */
	public static final int MINOR_0 = 255;

	/**
	 * Major version for DTLS 1.2.
	 * 
	 * @since 2.4
	 * @deprecated use {@link #MAJOR_1}
	 */
	@Deprecated
	public static final int MAJOR_1_2 = MAJOR_1;

	/**
	 * Minor version for DTLS 1.2.
	 * 
	 * @since 2.4
	 * @deprecated use {@link #MINOR_2}
	 */
	@Deprecated
	public static final int MINOR_1_2 = MINOR_2;

	/**
	 * Protocol version DTLS 1.2
	 * 
	 * @since 2.4
	 */
	public static final ProtocolVersion VERSION_DTLS_1_2 = new ProtocolVersion(MAJOR_1, MINOR_2);

	/**
	 * Protocol version DTLS 1.0
	 * 
	 * @since 2.5
	 */
	public static final ProtocolVersion VERSION_DTLS_1_0 = new ProtocolVersion(MAJOR_1, MINOR_0);

	/** The minor. */
	private final int minor;

	/** The major. */
	private final int major;

	/**
	 * Creates an instance representing DTLS version 1.2.
	 * 
	 * The version is represented as {254, 253} (1's complement of {1, 2}).
	 * 
	 * @deprecated use {@link #VERSION_DTLS_1_2} or {@link #valueOf(int, int)}
	 *             instead.
	 */
	@Deprecated
	public ProtocolVersion() {
		this.major = MAJOR_1;
		this.minor = MINOR_2;
	}

	/**
	 * Instantiates a new protocol version.
	 *
	 * @param major the major
	 * @param minor the minor
	 * @deprecated intended to became private. Use {@link #valueOf(int, int)}
	 *             instead.
	 */
	@Deprecated
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

	/**
	 * Compares this protocol version to another one.
	 * 
	 * Note that the comparison is done based on the <em>semantic</em> version,
	 * i.e. DTLS protocol version 1.0 (represented as major 254, minor 255) is
	 * considered <em>lower</em> than 1.2 (represented as major 254, minor 253)
	 * whereas the byte values representing version 1.0 are actually larger.
	 * 
	 * @param o the protocol version to compare to
	 * @return <em>0</em> if this version is exactly the same as the other
	 *         version, <em>-1</em> if this version is lower than the other
	 *         version or <em>1</em> if this version is higher than the other
	 *         version
	 */
	@Override
	public int compareTo(ProtocolVersion o) {

		if (this == o) {
			return 0;
		}

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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + major;
		result = prime * result + minor;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj == null) {
			return false;
		} else if (!(obj instanceof ProtocolVersion)) {
			return false;
		} else {
			ProtocolVersion other = (ProtocolVersion) obj;
			return major == other.major && minor == other.minor;
		}
	}

	@Override
	public String toString() {
		return Integer.toString(255 - major) + "." + Integer.toString(255 - minor);
	}

	/**
	 * Get protocol version value of the provided versions.
	 * 
	 * @param major major version
	 * @param minor minor version
	 * @return protocol version
	 */
	public static ProtocolVersion valueOf(int major, int minor) {
		if (major == MAJOR_1 && minor == MINOR_2) {
			return VERSION_DTLS_1_2;
		} else if (major == MAJOR_1 && minor == MINOR_0) {
			return VERSION_DTLS_1_0;
		} else {
			return new ProtocolVersion(major, minor);
		}
	}
}
