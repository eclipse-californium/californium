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

    /** Generate RST for a specified input. */
    public abstract EmptyMessage generateRst(RawData rawData);

    /** Parses message based on the raw data. */
    public Request parseRequest(RawData rawData, int code) {
        Request request = new Request(CoAP.Code.valueOf(code));
        parseMessage(request, rawData);
        return request;
    }

    /** Parses message based on the raw data. */
    public Response parseResponse(RawData rawData, int code) {
        Response response = new Response(CoAP.ResponseCode.valueOf(code));
        parseMessage(response, rawData);
        return response;
    }

    /** Parses message based on the raw data. */
    public EmptyMessage parseEmptyMessage(RawData rawData, int code) {
        if (!CoAP.isEmptyMessage(code)) {
            throw new MessageFormatException("Not an empty message: " + code);
        }

        EmptyMessage emptyMessage = new EmptyMessage(CoAP.Type.ACK);
        parseMessage(emptyMessage, rawData);
        return emptyMessage;
    }

    protected abstract void parseMessage(Message message, RawData rawData);

    public abstract int readMessageCode(RawData rawData);

    protected void parseOptionsAndPayload(DatagramReader reader, Message message) {
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
