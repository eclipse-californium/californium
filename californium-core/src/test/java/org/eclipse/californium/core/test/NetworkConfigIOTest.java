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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.test;

import org.junit.Ignore;

/**
 * This test tests the loading and storing of a NetworkConfig to the disk.
 */
@Ignore // Obsolete since we are back with using Strings as properties
public class NetworkConfigIOTest {

//	private static final String ARBITRARY_KEY = "ARBITRARY_KEY";
//	private static final String ARBITRARY_VALUE = "ARBITRARY_VALUE";
//	private static final int MY_TIMEOUT = 7;
//	private static final float MY_FACTOR = 7.7f;
//	
//	private static final File FILE = new File("californium.properties.test");
//	
//	@Before
//	@After
//	public void removeConfig() throws Exception {
//		System.gc(); // required because Java doesn't delete the file otherwise O_o
//		FILE.delete();
//	}
//	
//	@Test
//	public void test() throws IOException {
//		NetworkConfig c1 = new NetworkConfig();
//		c1.setAckTimeout(MY_TIMEOUT);
//		c1.setAckRandomFactor(MY_FACTOR);
//		c1.setArbitrary(ARBITRARY_KEY, ARBITRARY_VALUE);
//		c1.store(FILE);
//		
//		NetworkConfig c2 = new NetworkConfig(FILE);
//		assertTrue(c2.getAckTimeout() == MY_TIMEOUT);
//		assertTrue(c2.getAckRandomFactor() == MY_FACTOR);
//		assertEquals(c2.getArbitrary(ARBITRARY_KEY), ARBITRARY_VALUE);
//	}
}
