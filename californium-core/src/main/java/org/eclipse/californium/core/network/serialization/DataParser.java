/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Bosch Software Innovations GmbH - turn into utility class with static methods only
 *    Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.RawData;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.PAYLOAD_MARKER;

/**
 * Interface for parsing messages. Two implementations exists: TcpParser (based on CoAP over TCP RFC), and UDP parser,
 * based on original CoAP spec.
 */
public abstract class DataParser {

    /** Parses request out of raw data. */
    public Request parseRequest(RawData rawData) {
        DatagramReader reader = new DatagramReader(rawData.getBytes());
        MessageHeader header = parseHeader(reader);
        Request request = new Request(CoAP.Code.valueOf(header.getCode()));
        request.setMID(header.getMID());
        request.setType(header.getType());
        request.setToken(header.getToken());

        parseOptionsAndPayload(reader, request);
        return request;
    }

    /** Parses Response out of the raw data. */
    public Response parseResponse(RawData rawData) {
        DatagramReader reader = new DatagramReader(rawData.getBytes());
        MessageHeader header = parseHeader(reader);
        Response response = new Response(CoAP.ResponseCode.valueOf(header.getCode()));
        response.setMID(header.getMID());
        response.setType(header.getType());
        response.setToken(header.getToken());

        parseOptionsAndPayload(reader, response);
        return response;
    }

    /** Parses empty message out of the raw data. */
    public EmptyMessage parseEmptyMessage(RawData rawData) {
        DatagramReader reader = new DatagramReader(rawData.getBytes());
        MessageHeader header = parseHeader(reader);
        if (!CoAP.isEmptyMessage(header.getCode())) {
            throw new MessageFormatException("Code " + header.getCode() + " not an empty message");
        }

        EmptyMessage emptyMessage = new EmptyMessage(header.getType());
        emptyMessage.setMID(header.getMID());
        emptyMessage.setType(header.getType());
        emptyMessage.setToken(header.getToken());
        parseOptionsAndPayload(reader, emptyMessage);
        return emptyMessage;

    }

    /** Parses message code out of the message. */
    public MessageHeader parseHeader(RawData raw) {
        DatagramReader reader = new DatagramReader(raw.getBytes());
        return parseHeader(reader);
    }

    protected abstract MessageHeader parseHeader(DatagramReader reader);

    private void parseOptionsAndPayload(DatagramReader reader, Message message) {
        int currentOptionNumber = 0;
        byte nextByte = 0;

        // TODO detect malformed options
        while (reader.bytesAvailable()) {
            nextByte = reader.readNextByte();
            if (nextByte != PAYLOAD_MARKER) {
                // the first 4 bits of the byte represent the option delta
                int optionDeltaNibble = (0xF0 & nextByte) >> 4;
                currentOptionNumber = calculateNextOptionNumber(reader, currentOptionNumber, optionDeltaNibble);

                // the second 4 bits represent the option length
                int optionLengthNibble = 0x0F & nextByte;
                int optionLength = determineValueFromNibble(reader, optionLengthNibble);

                // read option
                Option option = new Option(currentOptionNumber);
                option.setValue(reader.readBytes(optionLength));

                // add option to message
                message.getOptions().addOption(option);
            } else break;
        }

        if (nextByte == PAYLOAD_MARKER) {
            // the presence of a marker followed by a zero-length payload must be processed as a message format error
            if (!reader.bytesAvailable()) {
                throw new MessageFormatException("Found payload marker (0xFF) but message contains no payload");
            } else {
                // get payload
                message.setPayload(reader.readBytesLeft());
            }
        } else {
            message.setPayload(new byte[0]); // or null?
        }
    }

    /**
     * Calculates the next option number based on the current option number and the option delta as specified in
     * RFC 7252, Section 3.1
     *
     * @param delta
     *            the 4-bit option delta value.
     * @return the next option number.
     * @throws MessageFormatException if the option number cannot be determined due to a message format error.
     */
    private int calculateNextOptionNumber(final DatagramReader reader, final int currentOptionNumber, final int delta) {
        return currentOptionNumber + determineValueFromNibble(reader, delta);
    }

    private int determineValueFromNibble(final DatagramReader reader, final int delta) {
        if (delta <= 12) {
            return delta;
        } else if (delta == 13) {
            return reader.read(8) + 13;
        } else if (delta == 14) {
            return reader.read(16) + 269;
        } else {
            throw new MessageFormatException("Message contains illegal option delta/length: " + delta);
        }
    }
}
