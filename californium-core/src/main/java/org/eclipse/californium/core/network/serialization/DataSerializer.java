package org.eclipse.californium.core.network.serialization;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;

/**
 * Serializes messages into wire format.
 */
public interface DataSerializer {
    byte[] serializeRequest(Request request);

    byte[] serializeResponse(Response response);

    byte[] serializeEmptyMessage(Message message);
}
