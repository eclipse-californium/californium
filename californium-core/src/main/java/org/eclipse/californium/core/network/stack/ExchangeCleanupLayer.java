package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange;

/**
 * A layer that reacts to user cancelled outgoing requests, and completes exchange, which causes state clean up.
 */
public class ExchangeCleanupLayer extends AbstractLayer {

	@Override public void sendRequest(Exchange exchange, Request request) {
		request.addMessageObserver(new CancelledMessageObserver(exchange));
		super.sendRequest(exchange, request);
	}

	private static class CancelledMessageObserver extends MessageObserverAdapter {

		private final Exchange exchange;

		CancelledMessageObserver(Exchange exchange) {
			this.exchange = exchange;
		}

		@Override public void onCancel() {
			if (!exchange.isComplete()) {
				exchange.setComplete();
			}
		}
	}
}
