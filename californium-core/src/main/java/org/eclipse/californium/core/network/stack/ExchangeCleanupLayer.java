package org.eclipse.californium.core.network.stack;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange;

/**
 * A layer that reacts to user cancelled outgoing requests, and completes exchange, which causes state clean up.
 */
public class ExchangeCleanupLayer extends AbstractLayer {

	private static final Logger LOGGER = Logger.getLogger(ExchangeCleanupLayer.class.getName());

	/**
	 * Adds a message observer to the request to be sent which
	 * completes the exchange if the request gets canceled.
	 * 
	 * @param exchange The (locally originating) exchange that the request is part of.
	 * @param request The outbound request.
	 */
	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		request.addMessageObserver(new CancelledMessageObserver(exchange));
		lower().sendRequest(exchange, request);
	}

	private static class CancelledMessageObserver extends MessageObserverAdapter {

		private final Exchange exchange;

		CancelledMessageObserver(final Exchange exchange) {
			this.exchange = exchange;
		}

		@Override
		public void onCancel() {

			if (!exchange.isComplete()) {
				LOGGER.log(Level.FINE, "completing canceled request [MID={0}, token={1}]",
						new Object[]{ exchange.getRequest().getMID(), exchange.getRequest().getTokenString() });
				exchange.setComplete();
			}
		}
	}
}
