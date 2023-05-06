package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.CoAP.SignalingCode;
import org.eclipse.californium.core.coap.option.SignalingOptionRegistry;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.SignalingMessage;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.util.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CapabilitiesSettingsLayer extends AbstractConnectionOrientedLayer {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(CapabilitiesSettingsLayer.class);

	@Override
	public void receiveRequest(Exchange exchange, Request request) {
		// TODO store request before to transfer it to upper layer once we get CSM from foreign peer ?
		super.receiveRequest(exchange, request);
	}
	
	@Override
	public void receiveResponse(Exchange exchange, Response response) {
		// TODO store request before to transfer it to upper layer once we get CSM from foreign peer ?
		super.receiveResponse(exchange, response);
	}
	
	@Override
	public void sendRequest(Exchange exchange, Request request) {
		// TODO store request to send it once we get CSM from foreign peer ?
		super.sendRequest(exchange, request);
	}
	
	@Override
	public void sendResponse(Exchange exchange, Response response) {
		// TODO store request to send it once we get CSM from foreign peer ?
		super.sendResponse(exchange, response);
	}
	
	
	@Override
	public void connected(EndpointContext context) {
		SignalingMessage cms = new SignalingMessage(SignalingCode.CSM);

		// TODO use max message size from config ?
		Option max_message_size = SignalingOptionRegistry.MAX_MESSAGE_SIZE.create(1152);
		Option block_wise_transfer = SignalingOptionRegistry.BLOCK_WISE_TRANSFER.create(Bytes.EMPTY);

		cms.setOptions(new OptionSet().addOptions(max_message_size, block_wise_transfer));

		cms.setDestinationContext(context);
		LOGGER.warn("Sending to {} : {}",context, cms);
		sendSignalingMessage(cms);

		super.connected(context);
	}

	@Override
	public void receivedSignalingMessage(SignalingMessage message) {
		LOGGER.warn("Receiving from {} : {}", message.getSourceContext(), message);
		// TODO store information about CSM somewhere ?
		super.receivedSignalingMessage(message);
	}
}
