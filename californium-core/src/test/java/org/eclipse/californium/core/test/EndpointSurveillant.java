package org.eclipse.californium.core.test;


import java.lang.reflect.Field;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.junit.Assert;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.Exchange.KeyUri;
import org.eclipse.californium.core.network.Matcher;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.deduplication.SweepDeduplicator;


public class EndpointSurveillant {
	
	private String name;

	// The HashMaps that have been extracted from the endpoint:
	private ConcurrentHashMap<KeyMID, Exchange> exchangesByMID; // Outgoing to match with inc ACK/RST
	private ConcurrentHashMap<KeyToken, Exchange> exchangesByToken; // Outgoing to match with inc responses
	private ConcurrentHashMap<KeyUri, Exchange> ongoingExchanges; // for blockwise
	private ConcurrentHashMap<KeyMID, Exchange> incommingMessages; // for deduplication

	private int exchangeLifecycle;
	private int sweepDuplicatorInterval;
	
	public EndpointSurveillant(String name, CoapEndpoint endpoint) {
		NetworkConfig config = endpoint.getConfig();
		this.exchangeLifecycle = config.getInt(NetworkConfig.Keys.EXCHANGE_LIFETIME);
		this.sweepDuplicatorInterval = config.getInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL);
		this.name = name;
		
		extractHashmaps(endpoint);
	}
	
	public void extractHashmaps(CoapEndpoint endpoint) {
		Matcher matcher = extractField(endpoint, "matcher");

		exchangesByMID = extractField(matcher, "exchangesByMID");
		exchangesByToken = extractField(matcher, "exchangesByToken");
		ongoingExchanges = extractField(matcher, "ongoingExchanges");

		SweepDeduplicator deduplicator = extractField(matcher, "deduplicator");
		incommingMessages = extractField(deduplicator, "incommingMessages");
	}
	
	@SuppressWarnings("unchecked")
	private static <T> T extractField(Object object, String name) {
		try {
			Field field = object.getClass().getDeclaredField(name);
			field.setAccessible(true);
			return (T) field.get(object);
		} catch (Exception e) {
			e.printStackTrace();
			Assert.assertTrue(false);
			return null;
		}
	}
	
	public void waitUntilDeduplicatorShouldBeEmpty() {
		try {
			int time = exchangeLifecycle + sweepDuplicatorInterval + 100;
			System.out.println("Wait until deduplicator should be empty ("+time/1000f+" seconds)");
			Thread.sleep(time);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	public void assertHashMapsEmpty() {
		try {
			Assert.assertEquals(0, exchangesByMID.size());
			Assert.assertEquals(0, exchangesByToken.size());
			Assert.assertEquals(0, ongoingExchanges.size());
			Assert.assertEquals(0, incommingMessages.size());
			System.out.println("Assertion passed: all HashMaps of "+name+" are empty");
		} catch (Error e) {
			System.out.println("Assertion failed: some HashMaps of "+name+" are NOT empty:");
			printHashmaps();
			throw e;
		}
	}
	
	public void printHashmaps() {
		StringBuffer buffer = new StringBuffer("");
		
		buffer.append("exchangesByMID: ");
		printContent(exchangesByMID, buffer);

		buffer.append("\nexchangesByToken: ");
		printContent(exchangesByToken, buffer);

		buffer.append("\nongoingExchanges: ");
		printContent(ongoingExchanges, buffer);

		buffer.append("\nincommingMessages: ");
		printContent(incommingMessages, buffer);
		
		System.out.println(buffer.toString());
	}
	
	private <T> void  printContent(ConcurrentHashMap<T, Exchange> map, StringBuffer buffer) {
		Set<Entry<T, Exchange>> entrySet = map.entrySet();
		buffer.append(entrySet.size()).append(" elements");
		int counter = 0 ;
		for (Map.Entry<T, Exchange> entry: entrySet) {
			buffer.append("\n  ").append(counter++).append(" ")
			      .append(entry.getKey()).append(" -> ")
			      .append(entry.getValue())
			      .append(" || Request:  ").append(entry.getValue().getRequest())
			      .append(" || Response: ").append(entry.getValue().getResponse());
		}
	}
	
}
