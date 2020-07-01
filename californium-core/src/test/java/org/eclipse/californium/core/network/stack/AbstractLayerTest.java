/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import static org.mockito.Mockito.mock;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Verifies behavior of {@code AbstractLayer}.
 *
 */
@Category(Small.class)
public class AbstractLayerTest {
	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Test(expected = NullPointerException.class)
	public void testSetLowerLayerRejectsNull() {
		Layer lowerLayer = mock(Layer.class);
		AbstractLayer layerToTest = new AbstractLayer() {
		};
		layerToTest.setLowerLayer(lowerLayer);

		layerToTest.setLowerLayer(null);
	}

	@Test(expected = NullPointerException.class)
	public void testSetUpperLayerRejectsNull() {
		Layer upperLayer = mock(Layer.class);
		AbstractLayer layerToTest = new AbstractLayer() {
		};
		layerToTest.setUpperLayer(upperLayer);

		layerToTest.setUpperLayer(null);
	}
}
