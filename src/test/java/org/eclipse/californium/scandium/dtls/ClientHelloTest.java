package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

import java.security.SecureRandom;

import org.junit.Before;
import org.junit.Test;

public class ClientHelloTest {

	ClientHello clientHello;
	
	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void testGetMessageLengthEqualsSerializedMessageLength() {
		givenAClientHelloWithEmptyExtensions();
		assertThat("ServerHello's anticipated message length does not match its real length",
				clientHello.getMessageLength(), is(clientHello.fragmentToByteArray().length));
	}
	
	private void givenAClientHelloWithEmptyExtensions() {
		clientHello = new ClientHello(new ProtocolVersion(), new SecureRandom(), false);
	}
}
