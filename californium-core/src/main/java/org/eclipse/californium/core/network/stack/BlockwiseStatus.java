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
package org.eclipse.californium.core.network.stack;

import java.util.ArrayList;
import java.util.List;

/**
 * This class represents the status of a blockwise transfer of a request or a
 * response.
 * 
 * This class is package private. Instances of this class are stored inside an
 * exchange and only accessed/modified by the class BlockwiseLayer.
 */
public class BlockwiseStatus {

	public static final int NO_OBSERVE = -1;
	
	/** The current num. */
	private int currentNum;
	
	/** The current szx. */
	private int currentSzx;
	
	private boolean randomAccess;
	
	private final int contentFormat;
	
	/** Indicates whether the blockwise transfer has completed. */
	private boolean complete;
	
	/*
	 * It would be nice if we could get rid of this. Currently, the Cf client
	 * needs it to mark a blockwise transferred notification as such. The
	 * problem is, that the server includes the observe option only in the first
	 * block of the notification and we still need to remember it, when the
	 * last block arrives (block-14).
	 */
	/** The observe sequence number of this blockwise transfer */
	private int observe = NO_OBSERVE;

	/*
	 * Unfortunately, we cannot use a ByteBuffer and just insert one payload
	 * after another. If a blockwise request is answered with a blockwise
	 * response, the first and second payload blocks are sent concurrently
	 * (blockwise-11). They might arrive out of order. If the first block goes
	 * lost, the client resends the last request block. Until the first response
	 * block arrives we might already have collected several response blocks.
	 * This is also the reason, why synchronization is required. (=>TODO)
	 * This might change in a future draft.
	 * UPDATE: This is no longer true since block-14.
	 */
	// Container for the payload of all blocks
	/** The blocks. */
	private ArrayList<byte[]> blocks = new ArrayList<byte[]>();

	/**
	 * Instantiates a new blockwise status.
	 * 
	 * @param contentFormat the initial Content-Format
	 */
	public BlockwiseStatus(int contentFormat) {
		this.contentFormat = contentFormat;
	}

	/**
	 * Instantiates a new blockwise status.
	 *
	 * @param contentFormat the initial Content-Format
	 * @param num the num
	 * @param szx the szx
	 */
	public BlockwiseStatus(int contentFormat, int num, int szx) {
		this.contentFormat = contentFormat;
		this.currentNum = num;
		this.currentSzx = szx;
	}
	
	/**
	 * Gets the current num.
	 *
	 * @return the current num
	 */
	public int getCurrentNum() {
		return currentNum;
	}

	/**
	 * Sets the current num.
	 *
	 * @param currentNum the new current num
	 */
	public void setCurrentNum(int currentNum) {
		this.currentNum = currentNum;
	}

	/**
	 * Gets the current szx.
	 *
	 * @return the current szx
	 */
	public int getCurrentSzx() {
		return currentSzx;
	}

	/**
	 * Sets the current szx.
	 *
	 * @param currentSzx the new current szx
	 */
	public void setCurrentSzx(int currentSzx) {
		this.currentSzx = currentSzx;
	}

	/**
	 * Returns the initial Content-Format, which must stay the same for the whole transfer.
	 * 
	 * @return the Content-Format of the body
	 */
	public int getContentFormat() {
		return contentFormat;
	}

	/**
	 * Checks if is complete.
	 *
	 * @return true, if is complete
	 */
	public boolean isComplete() {
		return complete;
	}

	/**
	 * Sets the complete.
	 *
	 * @param complete the new complete
	 */
	public void setComplete(boolean complete) {
		this.complete = complete;
	}
	
	/**
	 * Adds the specified block to the current list of blocks.
	 *
	 * @param block the block
	 */
	public void addBlock(byte[] block) {
		blocks.add(block);
	}
	
	/**
	 * Gets the number of blocks.
	 *
	 * @return the block count
	 */
	public int getBlockCount() {
		return blocks.size();
	}
	
	/**
	 * Gets the list of blocks.
	 *
	 * @return the blocks
	 */
	public List<byte[]> getBlocks() {
		return blocks;
	}
	
	public int getObserve() {
		return observe;
	}
	
	public void setObserve(int observe) {
		this.observe = observe;
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return String.format("[currentNum=%d, currentSzx=%d, complete=%b, random access=%b]",
				currentNum, currentSzx, complete, randomAccess);
	}

	public boolean isRandomAccess() {
		return randomAccess;
	}

	public void setRandomAccess(boolean randomAccess) {
		this.randomAccess = randomAccess;
	}
}
