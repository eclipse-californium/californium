package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.MatcherTestUtils;
import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.net.InetAddress;
import java.util.concurrent.ScheduledExecutorService;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@Category(Small.class) @RunWith(MockitoJUnitRunner.class)
public class CoapTcpStackTest {

	private static final NetworkConfig CONFIG = NetworkConfig.createStandardWithoutFile();

	@Mock private Outbox outbox;
	@Mock private MessageDeliverer deliverer;
	@Mock private ScheduledExecutorService executor;

	private CoapStack stack;

	@Before
	public void initialize() {
		stack = new CoapTcpStack(CONFIG, outbox);
		stack.setDeliverer(deliverer);
		stack.setExecutor(executor);

	}

	@Test public void sendEmptyMessageExpectSent() {
		EmptyMessage message = new EmptyMessage(CoAP.Type.CON);
		stack.sendEmptyMessage(null, message);

		verify(outbox).sendEmptyMessage(null, message);
	}


	@Test public void sendRstExpectNotSend() {
		Request request = new Request(CoAP.Code.GET);
		Exchange exchange = new Exchange(request, Origin.REMOTE, MatcherTestUtils.TEST_EXCHANGE_EXECUTOR);
		EmptyMessage message = new EmptyMessage(CoAP.Type.RST);
		stack.sendEmptyMessage(exchange, message);

		verify(outbox, never()).sendEmptyMessage(any(Exchange.class), any(EmptyMessage.class));
	}

	@Test public void sendRequestExpectSent() {
		Request message = new Request(CoAP.Code.GET);
		message.setDestinationContext(new AddressEndpointContext(InetAddress.getLoopbackAddress(), CoAP.DEFAULT_COAP_PORT));
		Exchange exchange = new Exchange(message, Origin.LOCAL, MatcherTestUtils.TEST_EXCHANGE_EXECUTOR);
		stack.sendRequest(exchange, message);

		verify(outbox).sendRequest(any(Exchange.class), eq(message));
	}


	@Test public void sendResponseExpectSent() {
		Request request = new Request(CoAP.Code.GET);
		Exchange exchange = new Exchange(request, Exchange.Origin.REMOTE, MatcherTestUtils.TEST_EXCHANGE_EXECUTOR);
		exchange.setRequest(request);

		Response response = new Response(CoAP.ResponseCode.CONTENT);
		stack.sendResponse(exchange, response);

		verify(outbox).sendResponse(exchange, response);
	}
}
