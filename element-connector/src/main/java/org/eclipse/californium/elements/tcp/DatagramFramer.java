/*******************************************************************************
 * Copyright (c) 2016 Amazon Web Services.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import org.eclipse.californium.elements.RawData;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.List;

/**
 * Converts stream of bytes over TCP connection into distinct datagrams based on CoAP over TCP spec.
 */
public class DatagramFramer extends ByteToMessageDecoder {

	public static int getLengthFieldSize(int len) {
		if (len > 15 || len < 0) {
			throw new IllegalArgumentException("Invalid len field: " + len);
		}

		if (len == 13) {
			return 1;
		} else if (len == 14) {
			return 2;
		} else if (len == 15) {
			return 4;
		} else {
			return 0;
		}
	}

	@Override protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
		while (in.readableBytes() > 0) {
			byte firstByte = in.getByte(in.readerIndex());
			int lengthNibble = (firstByte & 0xF0) >>> 4;
			int tokenNibble = firstByte & 0x0F;

			int lengthFieldSize = getLengthFieldSize(lengthNibble);
			int coapHeaderSize = getCoapHeaderSize(lengthFieldSize, tokenNibble);
			if (in.readableBytes() < coapHeaderSize) {
				// Not enough data, no point in continuing.
				return;
			}

			int bodyLength = getBodyLength(in, lengthNibble, lengthFieldSize);
			if (in.readableBytes() < coapHeaderSize + bodyLength) {
				// Whole body not available yet.
				return;
			}

			byte[] data = new byte[coapHeaderSize + bodyLength];
			in.readBytes(data);
			// This is TCP connector, so we know remote address is InetSocketAddress.
			InetSocketAddress socketAddress = (InetSocketAddress) ctx.channel().remoteAddress();
			RawData rawData = new RawData(data, socketAddress);
			out.add(rawData);
		}
	}

	private int getBodyLength(ByteBuf in, int lengthNibble, int fieldSize) {
		byte data[] = new byte[fieldSize];
		in.getBytes(in.readerIndex() + 1, data);

		switch (fieldSize) {
		case 0:
			return lengthNibble;
		case 1:
			return new BigInteger(1, data).intValue() + 13;
		case 2:
			return new BigInteger(1, data).intValue() + 269;
		case 4:
			// Possible overflow here, but is anybody reallying sending 2GB messages around?
			return new BigInteger(1, data).intValue() + 65805;
		default:
			throw new IllegalArgumentException("Invalid field size: " + fieldSize);
		}
	}

	private int getCoapHeaderSize(int lengthFieldSize, int tokenFieldSize) {
		// https://tools.ietf.org/html/draft-ietf-core-coap-tcp-tls-02
		// 2 4-bit nibbles (len + tlk_len) + length field + code field + token field.
		return 2 + lengthFieldSize + tokenFieldSize;

	}
}
