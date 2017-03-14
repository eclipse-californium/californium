package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;

@Category(Small.class) @RunWith(Parameterized.class)
public class CoapStackTest {

	private static final NetworkConfig CONFIG = NetworkConfig.createStandardWithoutFile();

	private final CoapStack stack;
	private final Outbox outbox;

	public CoapStackTest(CoapStack stack, Outbox outbox) {
		this.stack = stack;
		this.stack.setExecutor(Executors.newSingleThreadScheduledExecutor());
		this.outbox = outbox;
	}

	@Parameterized.Parameters public static List<Object[]> parameters() {
		Outbox udpOutbox = mock(Outbox.class);
		Outbox tcpOutbox = mock(Outbox.class);

		List<Object[]> parameters = new ArrayList<>();
		parameters.add(new Object[]{new CoapTcpStack(CONFIG, tcpOutbox), tcpOutbox});
		parameters.add(new Object[]{new CoapUdpStack(CONFIG, udpOutbox), udpOutbox});
		return parameters;
	}

	@Test public void cancelledMessageExpectExchangeComplete() {
		Request request = new Request(CoAP.Code.GET);

		ArgumentCaptor<Exchange> exchangeCaptor = ArgumentCaptor.forClass(Exchange.class);
		doNothing().when(outbox).sendRequest(exchangeCaptor.capture(), eq(request));

		stack.sendRequest(request);

		// Capture exchange
		Exchange exchange = exchangeCaptor.getValue();
		assertFalse(exchange.isComplete());

		request.setCanceled(true);
		assertTrue(exchange.isComplete());
	}
}
