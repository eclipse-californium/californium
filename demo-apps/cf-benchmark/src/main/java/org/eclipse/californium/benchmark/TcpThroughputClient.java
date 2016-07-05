package org.eclipse.californium.benchmark;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;

import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class TcpThroughputClient {

	public static void main(String[] args) {
		CoapClient coapClient = new CoapClient("coap+tcp", "localhost", CoAP.DEFAULT_COAP_PORT, "echo");

		Random random = new Random(0);
		long messages = 200_000;
		long total = 0;

		long start = System.nanoTime();
		for (int i = 0; i < messages; i++) {
			byte data[] = new byte[random.nextInt(1024 * 2)];
			total += data.length;

			random.nextBytes(data);
			CoapResponse put = coapClient.put(data, 60);

			if (put == null || !put.isSuccess()) {
				throw new RuntimeException("Did not receive response on request #" + i);
			}

			if (!Arrays.equals(data, put.getPayload())) {
				throw new RuntimeException("Mismatched response on request #" + i);
			}
		}
		long end = System.nanoTime();

		System.out.println(messages + " messages in " + TimeUnit.NANOSECONDS.toMillis(end - start) + "ms");
		System.out.println("Rate " + messages / TimeUnit.NANOSECONDS.toSeconds(end - start) + " msg/s");
		System.out.println("Bandwidth " + total / TimeUnit.NANOSECONDS.toSeconds(end - start) / 1024 / 1024 + " MB/s");
	}
}
