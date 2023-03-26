/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

/**
 * Algorithm names used by the JCE.
 * 
 * @since 3.3
 */
public interface JceNames {

	/**
	 * Key algorithm EC to be used by KeyFactory.
	 */
	public String EC = "EC";
	/**
	 * Key algorithm EC v2 (RFC 5958), not to be used by KeyFactory.
	 */
	public String ECv2 = "EC.v2";
	/**
	 * Key algorithm RSA to be used by KeyFactory.
	 */
	public String RSA = "RSA";
	/**
	 * Key algorithm DSA to be used by KeyFactory.
	 */
	public String DSA = "DSA";
	/**
	 * Key algorithm DH to be used by KeyFactory.
	 */
	public String DH = "DH";
	/**
	 * Key algorithm EdDSA (RFC 8422).
	 */
	public String EDDSA = "EdDSA";
	/**
	 * Key algorithm ED25519 (RFC 8422).
	 */
	public String ED25519 = "Ed25519";
	/**
	 * Key algorithm Ed25519 v2 (RFC 8410), not to be used by KeyFactory.
	 */
	public String ED25519v2 = "Ed25519.v2";
	/**
	 * OID key algorithm ED25519
	 * (<a href="https://datatracker.ietf.org/doc/html/rfc8410#section-3" target
	 * ="_blank"> RFC 8410, 3. Curve25519 and Curve448 Algorithm
	 * Identifiers</a>).
	 */
	public String OID_ED25519 = "OID.1.3.101.112";
	/**
	 * Key algorithm ED448 (RFC 8422).
	 */
	public String ED448 = "Ed448";
	/**
	 * Key algorithm Ed448 v2 (RFC 8410), not to be used by KeyFactory.
	 */
	public String ED448v2 = "Ed448.v2";
	/**
	 * OID key algorithm ED448
	 * (<a href="https://datatracker.ietf.org/doc/html/rfc8410#section-3" target
	 * ="_blank"> RFC 8410, 3. Curve25519 and Curve448 Algorithm
	 * Identifiers</a>).
	 */
	public String OID_ED448 = "OID.1.3.101.113";
	/**
	 * Key algorithm X25519 (RFC 8422).
	 */
	public String X25519 = "X25519";
	/**
	 * Key algorithm X25519 v2 (RFC 8410), not to be used by KeyFactory.
	 */
	public String X25519v2 = "X25519.v2";
	/**
	 * OID key algorithm X25519
	 * (<a href="https://datatracker.ietf.org/doc/html/rfc8410#section-3" target
	 * ="_blank"> RFC 8410, 3. Curve25519 and Curve448 Algorithm
	 * Identifiers</a>).
	 */
	public String OID_X25519 = "OID.1.3.101.110";
	/**
	 * Key algorithm X448 (RFC 8422).
	 */
	public String X448 = "X448";
	/**
	 * Key algorithm X448 v2 (RFC 8410), not to be used by KeyFactory.
	 */
	public String X448v2 = "X448.v2";
	/**
	 * OID key algorithm X448
	 * (<a href="https://datatracker.ietf.org/doc/html/rfc8410#section-3" target
	 * ="_blank"> RFC 8410, 3. Curve25519 and Curve448 Algorithm
	 * Identifiers</a>).
	 */
	public String OID_X448 = "OID.1.3.101.111";

	/**
	 * Name of environment variable to specify the JCE.
	 * 
	 * Usage via environment variable:
	 * <pre>
	 * unix:
	 * export CALIFORNIUM_JCE_PROVIDER=BC
	 * ...
	 * java ... 
	 * </pre>
	 * 
	 * or via system property:
	 * 
	 * <pre>
	 * java -DCALIFORNIUM_JCE_PROVIDER=BC ...
	 * </pre>
	 * 
	 * Requires to add the required jars to the classpath!
	 */
	public String CALIFORNIUM_JCE_PROVIDER = "CALIFORNIUM_JCE_PROVIDER";
	/**
	 * Value for {@link #CALIFORNIUM_JCE_PROVIDER} to use only the provided JCE.
	 */
	public String JCE_PROVIDER_SYSTEM = "SYSTEM";
	/**
	 * Value for {@link #CALIFORNIUM_JCE_PROVIDER} to use Bouncy Castle as JCE.
	 * 
	 * <b>Note:</b> the default mechanism in BC to create a secure random may be
	 * blocking. That may block the startup for a couple of seconds, maybe 60s
	 * and more.
	 * 
	 * @see #JCE_PROVIDER_BOUNCY_CASTLE_NON_BLOCKING_RANDOM
	 */
	public String JCE_PROVIDER_BOUNCY_CASTLE = "BC";
	/**
	 * Value for {@link #CALIFORNIUM_JCE_PROVIDER} to use Bouncy Castle as JCE
	 * with non blocking secure random.
	 * 
	 * <b>Note:</b> using non-blocking secure random prevents BC from being
	 * blocked on startup, but may result in weaker secure random.
	 * 
	 * @see #JCE_PROVIDER_BOUNCY_CASTLE
	 */
	public String JCE_PROVIDER_BOUNCY_CASTLE_NON_BLOCKING_RANDOM = "BC_NON_BLOCKING_RANDOM";
	/**
	 * Value for {@link #CALIFORNIUM_JCE_PROVIDER} to use ed25519-java as JCE
	 * for EdDSA.
	 */
	public String JCE_PROVIDER_NET_I2P_CRYPTO = "I2P";
	/**
	 * Name of environment variable to specify, if the used JCE is tested for
	 * the ECDSA vulnerability
	 * <a href= "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21449"
	 * target="_blank">ECDSA vulnerability, CVE-2022-21449</a>.
	 * 
	 * The default is to test it. If the value of this environment variable is
	 * set to {@code false}, the test is suppressed and no additional checks for
	 * such signatures are done.
	 * 
	 * @since 3.5
	 */
	public String CALIFORNIUM_JCE_ECDSA_FIX = "CALIFORNIUM_JCE_ECDSA_FIX";

}
