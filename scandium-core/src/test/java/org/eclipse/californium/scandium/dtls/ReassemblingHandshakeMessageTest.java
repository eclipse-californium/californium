/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import org.eclipse.californium.elements.category.Small;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Category(Small.class)
public class ReassemblingHandshakeMessageTest {

	public static final Logger LOGGER = LoggerFactory.getLogger(ReassemblingHandshakeMessageTest.class);

	private static final int MAX_FRAGMENT_SIZE = 100;
	private static final int MESSAGE_SIZE = 3000;
	private static final int MESSAGE_SEQN = 1;
	private static final int OVERLAPS = 10;

	private Random rand = new Random();
	private byte[] payload;
	private List<FragmentedHandshakeMessage> fragments;

	@Before
	public void setUp() {
		payload = new byte[MESSAGE_SIZE];
		rand.nextBytes(payload);
		fragments = new LinkedList<>();
		int fragmentOffset = 0;
		while (fragmentOffset < payload.length) {
			int fragmentLength = Math.min(MAX_FRAGMENT_SIZE, payload.length - fragmentOffset);
			byte[] fragment = new byte[fragmentLength];
			System.arraycopy(payload, fragmentOffset, fragment, 0, fragmentLength);
			FragmentedHandshakeMessage msg = new FragmentedHandshakeMessage(HandshakeType.CERTIFICATE, MESSAGE_SIZE,
					MESSAGE_SEQN, fragmentOffset, fragment);
			fragments.add(msg);
			fragmentOffset += fragmentLength;
		}
	}

	private void unorder() {
		for (int index = 0; index < fragments.size(); ++index) {
			int newIndex = rand.nextInt(fragments.size());
			FragmentedHandshakeMessage message = fragments.remove(index);
			fragments.add(newIndex, message);
		}
	}

	private void overlap(int quoteBefore, int quoteAfter) {
		for (int i=0; i< OVERLAPS; ++i) {
			int index = rand.nextInt(fragments.size() - 2) + 1;
			FragmentedHandshakeMessage message = quoteAfter > 0 ? fragments.remove(index) : fragments.get(index);
			int offset = message.getFragmentOffset() - (message.getFragmentLength() * quoteBefore) / 100;
			int length = message.getFragmentLength() * (100 + quoteAfter) / 100;
			if (offset < 0) {
				offset = 0;
			} else if (offset >= MESSAGE_SIZE) {
				offset = MESSAGE_SIZE - 2;
			}
			if (length <= 0) {
				length = 1;
			} else if (offset + length >= MESSAGE_SIZE) {
				length = MESSAGE_SIZE - offset - 1;
			}
			byte[] fragment = new byte[length];
			System.arraycopy(payload, offset, fragment, 0, length);
			message = new FragmentedHandshakeMessage(HandshakeType.CERTIFICATE, MESSAGE_SIZE, MESSAGE_SEQN, offset,
					fragment);
			fragments.add(index, message);
		}
	}

	private void log(FragmentedHandshakeMessage msg) {
		LOGGER.info(" fragment [{}:{})", msg.getFragmentOffset(), msg.getFragmentOffset() + msg.getFragmentLength());
	}

	private void log() {
		for (FragmentedHandshakeMessage msg : fragments) {
			log(msg);
		}
	}

	@Test
	public void testReassembleFragmentedHandshakeMessages() {
		boolean complete = false;
		ReassemblingHandshakeMessage message = new ReassemblingHandshakeMessage(fragments.get(0));
		for (FragmentedHandshakeMessage msg : fragments) {
			assertFalse("message completed with left fragments", complete);
			message.add(msg);
			complete = message.isComplete();
			LOGGER.info("{}", message);
		}
		assertTrue("message incomplete", complete);
		assertArrayEquals(payload, message.fragmentToByteArray());
	}

	@Test
	public void testReassembleFragmentedHandshakeMessagesUnordered() {
		unorder();
		boolean complete = false;
		ReassemblingHandshakeMessage message = new ReassemblingHandshakeMessage(fragments.get(0));
		for (FragmentedHandshakeMessage msg : fragments) {
			assertFalse("message completed with left fragments", complete);
			message.add(msg);
			complete = message.isComplete();
			LOGGER.info("{}", message);
		}
		assertTrue("message incomplete", complete);
		assertArrayEquals(payload, message.fragmentToByteArray());
	}

	@Test
	public void testReassembleFragmentedHandshakeMessagesOverlapping() {
		overlap(100, 100);
		overlap(50, 50);
		overlap(50, -50);
		boolean complete = false;
		ReassemblingHandshakeMessage message = new ReassemblingHandshakeMessage(fragments.get(0));
		for (FragmentedHandshakeMessage msg : fragments) {
			assertFalse("message completed with left fragments", complete);
			message.add(msg);
			complete = message.isComplete();
			LOGGER.info("{}", message);
		}
		assertTrue("message incomplete", complete);
		assertArrayEquals(payload, message.fragmentToByteArray());
	}

	@Test
	public void testReassembleFragmentedHandshakeMessagesOverlappingUnordered() {
		overlap(50, 50);
		overlap(100, 100);
		overlap(50, -50);
		unorder();
		log();
		boolean complete = false;
		ReassemblingHandshakeMessage message = new ReassemblingHandshakeMessage(fragments.get(0));
		for (FragmentedHandshakeMessage msg : fragments) {
			message.add(msg);
			complete = message.isComplete() || complete;
			log(msg);
			LOGGER.info("{}", message);
		}
		assertTrue("message incomplete", complete);
		assertArrayEquals(payload, message.fragmentToByteArray());
	}

	@Test
	public void testReassembleIncompleteFragmentedHandshakeMessages() {
		int index = rand.nextInt(fragments.size());
		fragments.remove(index);
		boolean complete = false;
		ReassemblingHandshakeMessage message = new ReassemblingHandshakeMessage(fragments.get(0));
		for (FragmentedHandshakeMessage msg : fragments) {
			assertFalse("message completed with left fragments", complete);
			message.add(msg);
			complete = message.isComplete();
			LOGGER.info("{}", message);
		}
		assertFalse("message completed with incomplete fragments", complete);
	}

	@Test
	public void testAddFragmentedHandshakeMessageAfterComplete() {
		boolean complete = false;
		FragmentedHandshakeMessage first = fragments.get(0);
		FragmentedHandshakeMessage additionalMsg = new FragmentedHandshakeMessage(HandshakeType.CERTIFICATE,
				MESSAGE_SIZE, MESSAGE_SEQN, first.getFragmentLength(), first.fragmentToByteArray());
		fragments.add(additionalMsg);
		ReassemblingHandshakeMessage message = new ReassemblingHandshakeMessage(first);
		for (FragmentedHandshakeMessage msg : fragments) {
			message.add(msg);
			complete = message.isComplete();
			LOGGER.info("{}", message);
		}
		assertTrue("message incomplete", complete);
		assertArrayEquals(payload, message.fragmentToByteArray());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDifferentMessageType() {
		FragmentedHandshakeMessage first = fragments.get(0);
		ReassemblingHandshakeMessage message = new ReassemblingHandshakeMessage(first);
		FragmentedHandshakeMessage msg = new FragmentedHandshakeMessage(HandshakeType.SERVER_KEY_EXCHANGE, MESSAGE_SIZE,
				MESSAGE_SEQN, first.getFragmentLength(), first.fragmentToByteArray());
		message.add(msg);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDifferentMessageSize() {
		FragmentedHandshakeMessage first = fragments.get(0);
		ReassemblingHandshakeMessage message = new ReassemblingHandshakeMessage(first);
		FragmentedHandshakeMessage msg = new FragmentedHandshakeMessage(HandshakeType.CERTIFICATE, MESSAGE_SIZE - 1,
				MESSAGE_SEQN, first.getFragmentLength(), first.fragmentToByteArray());
		message.add(msg);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDifferentMessageSeqn() {
		FragmentedHandshakeMessage first = fragments.get(0);
		ReassemblingHandshakeMessage message = new ReassemblingHandshakeMessage(first);
		FragmentedHandshakeMessage msg = new FragmentedHandshakeMessage(HandshakeType.CERTIFICATE, MESSAGE_SIZE,
				MESSAGE_SEQN + 1, first.getFragmentLength(), first.fragmentToByteArray());
		message.add(msg);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testFragmentExceedMessageSize() {
		FragmentedHandshakeMessage first = fragments.get(0);
		ReassemblingHandshakeMessage message = new ReassemblingHandshakeMessage(first);
		FragmentedHandshakeMessage msg = new FragmentedHandshakeMessage(HandshakeType.CERTIFICATE, MESSAGE_SIZE,
				MESSAGE_SEQN + 1, first.getFragmentLength(), payload);
		message.add(msg);
	}
}
