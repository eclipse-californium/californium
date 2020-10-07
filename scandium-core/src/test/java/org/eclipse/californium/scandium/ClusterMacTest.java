/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
package org.eclipse.californium.scandium;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.DatagramPacket;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class ClusterMacTest {

	private SecretKey key;
	private DatagramPacket smallRecord;
	private DatagramPacket largeRecord;

	@Before
	public void init() {
		Random random = RandomManager.currentRandom();
		byte[] init = new byte[16];
		random.nextBytes(init);
		key = SecretUtil.create(init, "Mac");
		byte[] small = new byte[30];
		random.nextBytes(small);
		small[DtlsClusterConnector.CLUSTER_ADDRESS_LENGTH_OFFSET] = 4;
		byte[] large = new byte[120];
		random.nextBytes(large);
		large[DtlsClusterConnector.CLUSTER_ADDRESS_LENGTH_OFFSET] = 4;
		smallRecord = new DatagramPacket(small, small.length);
		largeRecord = new DatagramPacket(large, large.length);
	}

	@Test
	public void testSmallRecordClusterMac() throws Exception {
		Mac mac = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8.getThreadLocalPseudoRandomFunctionMac();
		mac.init(key);

		byte[] macBytes1 = DtlsManagedClusterConnector.calculateClusterMac(mac, smallRecord);

		DtlsManagedClusterConnector.setClusterMac(mac, smallRecord);

		byte[] macBytes2 = DtlsManagedClusterConnector.calculateClusterMac(mac, smallRecord);

		assertTrue(DtlsManagedClusterConnector.validateClusterMac(mac, smallRecord));

		assertArrayEquals(macBytes1, macBytes2);

		byte[] data = smallRecord.getData();

		data[DtlsClusterConnector.CLUSTER_ADDRESS_OFFSET] += 1;

		assertFalse(DtlsManagedClusterConnector.validateClusterMac(mac, smallRecord));
	}

	@Test
	public void testSmallRecordWithOffsetClusterMac() throws Exception {
		int offset = 6;

		Mac mac = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8.getThreadLocalPseudoRandomFunctionMac();
		mac.init(key);

		byte[] data = smallRecord.getData();
		data[offset + DtlsClusterConnector.CLUSTER_ADDRESS_LENGTH_OFFSET] = 4;
		smallRecord.setData(data, offset, data.length - offset);

		byte[] macBytes1 = DtlsManagedClusterConnector.calculateClusterMac(mac, smallRecord);

		DtlsManagedClusterConnector.setClusterMac(mac, smallRecord);

		byte[] macBytes2 = DtlsManagedClusterConnector.calculateClusterMac(mac, smallRecord);

		assertTrue(DtlsManagedClusterConnector.validateClusterMac(mac, smallRecord));

		assertArrayEquals(macBytes1, macBytes2);

		data[offset + DtlsClusterConnector.CLUSTER_ADDRESS_OFFSET] += 1;

		assertFalse(DtlsManagedClusterConnector.validateClusterMac(mac, smallRecord));
	}

	@Test
	public void testLargeRecordClusterMac() throws Exception {
		Mac mac = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8.getThreadLocalPseudoRandomFunctionMac();
		mac.init(key);

		byte[] macBytes1 = DtlsManagedClusterConnector.calculateClusterMac(mac, largeRecord);

		DtlsManagedClusterConnector.setClusterMac(mac, largeRecord);

		byte[] macBytes2 = DtlsManagedClusterConnector.calculateClusterMac(mac, largeRecord);

		assertTrue(DtlsManagedClusterConnector.validateClusterMac(mac, largeRecord));

		assertArrayEquals(macBytes1, macBytes2);

		byte[] data = largeRecord.getData();
		data[DtlsClusterConnector.CLUSTER_ADDRESS_OFFSET] += 1;

		assertFalse(DtlsManagedClusterConnector.validateClusterMac(mac, largeRecord));
	}

	@Test
	public void testLargeRecordWithOffsetClusterMac() throws Exception {
		int offset = 10;

		Mac mac = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8.getThreadLocalPseudoRandomFunctionMac();
		mac.init(key);

		byte[] data = largeRecord.getData();
		data[offset + DtlsClusterConnector.CLUSTER_ADDRESS_LENGTH_OFFSET] = 4;
		largeRecord.setData(data, offset, data.length - offset);

		byte[] macBytes1 = DtlsManagedClusterConnector.calculateClusterMac(mac, largeRecord);

		DtlsManagedClusterConnector.setClusterMac(mac, largeRecord);

		byte[] macBytes2 = DtlsManagedClusterConnector.calculateClusterMac(mac, largeRecord);

		assertTrue(DtlsManagedClusterConnector.validateClusterMac(mac, largeRecord));

		assertArrayEquals(macBytes1, macBytes2);

		data[offset + DtlsClusterConnector.CLUSTER_ADDRESS_OFFSET] += 1;

		assertFalse(DtlsManagedClusterConnector.validateClusterMac(mac, largeRecord));

	}
}
