package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;

import java.util.concurrent.ScheduledExecutorService;

/**
 * CoapStack is what CoapEndpoint uses to send messages through distinct layers.
 */
public interface CoapStack {

	// delegate to top
	void sendRequest(Request request);

	// delegate to top
	void sendResponse(Exchange exchange, Response response);

	// delegate to top
	void sendEmptyMessage(Exchange exchange, EmptyMessage message);

	// delegate to bottom
	void receiveRequest(Exchange exchange, Request request);

	// delegate to bottom
	void receiveResponse(Exchange exchange, Response response);

	// delegate to bottom
	void receiveEmptyMessage(Exchange exchange, EmptyMessage message);

	void setExecutor(ScheduledExecutorService executor);

	void setDeliverer(MessageDeliverer deliverer);

	void destroy();

	boolean hasDeliverer();
}
