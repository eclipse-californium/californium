package org.eclipse.californium.core.test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.core.server.resources.ResourceAttributes;
import org.junit.Before;
import org.junit.Test;
import org.junit.Assert;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class LinkFormatTest {
	private Resource root;
	private Request request1, request2, request3;

	@Before
	public void setup() {
		root = new CoapResource("");
		Resource sensors = new CoapResource("sensors");
		Resource actors = new CoapResource("actors");
		Resource temp = new CoapResource("temp");
		Resource light = new CoapResource("light");
		Resource blinds = new CoapResource("blinds");

		root.add(sensors);
		root.add(actors);

		sensors.add(temp);
		sensors.add(light);
		sensors.getAttributes().setTitle("Sensor Index");

		actors.add(blinds);
		actors.getAttributes().setTitle("Actor Index");

		temp.getAttributes().addResourceType("temperature-c");
		temp.getAttributes().addInterfaceDescription("sensor");
		temp.getAttributes().addAttribute("foo");
		temp.getAttributes().addAttribute("bar", "one");
		temp.getAttributes().addAttribute("bar", "two");

		light.getAttributes().addResourceType("light-lux");
		light.getAttributes().addInterfaceDescription("sensor");

		blinds.getAttributes().addResourceType("angle");
		blinds.getAttributes().addInterfaceDescription("actor");

		request1 = new Request(Code.GET);
		request1.setURI("/.well-known/core?if=sensor");
		request2 = new Request(Code.GET);
		request2.setURI("/.well-known/core?if=sensor&rt=light-lux");
		request3 = new Request(Code.GET);
		request3.setURI("/.well-known/core?if=sensor&rt=angle");

	}

	@Test
	public void testMatchesFixed() {
		StringBuilder buffer = new StringBuilder();
		serializeTreeNewMatches(root, request1.getOptions().getUriQuery(), buffer);
		System.out.println("Result for request: /.well-known/core?if=sensor  with fixed matches() method:");
		System.out.println(buffer.toString() + "\n");
		Assert.assertEquals(
				"</sensors/light>;if=\"sensor\";rt=\"light-lux\""
						+ ",</sensors/temp>;bar=\"one two\";foo;if=\"sensor\";rt=\"temperature-c\",",
				buffer.toString());
	}

	@Test
	public void testMatchesOld() {
		StringBuilder buffer = new StringBuilder();
		serializeTreeOldMatches(root, request1.getOptions().getUriQuery(), buffer);
		System.out.println("Result for request: /.well-known/core?if=sensor  with old matches() method:");
		System.out.println(buffer.toString() + "\n");
		Assert.assertEquals(
				"</sensors/light>;if=\"sensor\";rt=\"light-lux\""
						+ ",</sensors/temp>;bar=\"one two\";foo;if=\"sensor\";rt=\"temperature-c\",",
				buffer.toString());
	}
	
	@Test
	public void testMatchesFixed2() {
		StringBuilder buffer = new StringBuilder();
		serializeTreeNewMatches(root, request2.getOptions().getUriQuery(), buffer);
		System.out.println("Result for request: /.well-known/core?if=sensor&rt=light-lux  with fixed matches() method:");
		System.out.println(buffer.toString() + "\n");
		Assert.assertEquals(
				"</sensors/light>;if=\"sensor\";rt=\"light-lux\",",
				buffer.toString());
	}
	
	@Test
	public void testMatchesOld2() {
		StringBuilder buffer = new StringBuilder();
		serializeTreeOldMatches(root, request2.getOptions().getUriQuery(), buffer);
		System.out.println("Result for request: /.well-known/core?if=sensor&rt=light-lux  with old matches() method:");
		System.out.println(buffer.toString() + "\n");
		Assert.assertEquals(
				"</sensors/light>;if=\"sensor\";rt=\"light-lux\",",
				buffer.toString());
	}
	
	@Test
	public void testMatchesFixed3() {
		StringBuilder buffer = new StringBuilder();
		serializeTreeNewMatches(root, request3.getOptions().getUriQuery(), buffer);
		System.out.println("Result for request: /.well-known/core?if=sensor&rt=angle  with fixed matches() method:");
		System.out.println(buffer.toString() + "\n");
		Assert.assertEquals(
				"",
				buffer.toString());
	}
	
	@Test
	public void testMatchesOld3() {
		StringBuilder buffer = new StringBuilder();
		serializeTreeOldMatches(root, request3.getOptions().getUriQuery(), buffer);
		System.out.println("Result for request: /.well-known/core?if=sensor&rt=angle  with old matches() method:");
		System.out.println(buffer.toString() + "\n");
		Assert.assertEquals(
				"",
				buffer.toString());
	}

	/**
	 * Serialize method from LinkFormat class with fixed matches method
	 * 
	 * @param resource
	 * @param queries
	 * @param buffer
	 */
	public static void serializeTreeNewMatches(Resource resource, List<String> queries, StringBuilder buffer) {
		// add the current resource to the buffer
		if (resource.isVisible() && matchesFixed(resource, queries)) {
			buffer.append(LinkFormat.serializeResource(resource));
		}

		// sort by resource name
		List<Resource> childs = new ArrayList<Resource>(resource.getChildren());
		Collections.sort(childs, new Comparator<Resource>() {
			@Override
			public int compare(Resource o1, Resource o2) {
				return o1.getName().compareTo(o2.getName());
			}
		});

		for (Resource child : childs) {
			serializeTreeNewMatches(child, queries, buffer);
		}
	}

	/**
	 * Serialize method from LinkFormat class with old method
	 * 
	 * @param resource
	 * @param queries
	 * @param buffer
	 */
	public static void serializeTreeOldMatches(Resource resource, List<String> queries, StringBuilder buffer) {
		// add the current resource to the buffer
		if (resource.isVisible() && matchesOld(resource, queries)) {
			buffer.append(LinkFormat.serializeResource(resource));
		}

		// sort by resource name
		List<Resource> childs = new ArrayList<Resource>(resource.getChildren());
		Collections.sort(childs, new Comparator<Resource>() {
			@Override
			public int compare(Resource o1, Resource o2) {
				return o1.getName().compareTo(o2.getName());
			}
		});

		for (Resource child : childs) {
			serializeTreeOldMatches(child, queries, buffer);
		}
	}

	/**
	 * Matches method before fix
	 * 
	 * @param resource
	 * @param queries
	 * @return
	 */
	public static boolean matchesOld(Resource resource, List<String> queries) {

		if (resource == null)
			return false;
		if (queries == null || queries.size() == 0)
			return true;

		ResourceAttributes attributes = resource.getAttributes();
		String path = resource.getPath() + resource.getName();

		for (String s : queries) {
			int delim = s.indexOf("=");
			if (delim != -1) {

				// split name-value-pair
				String attrName = s.substring(0, delim);
				String expected = s.substring(delim + 1);

				if (attrName.equals(LinkFormat.LINK)) {
					if (expected.endsWith("*")) {
						return path.startsWith(expected.substring(0, expected.length() - 1));
					} else {
						return path.equals(expected);
					}
				} else if (attributes.containsAttribute(attrName)) {
					// lookup attribute value
					for (String actual : attributes.getAttributeValues(attrName)) {

						// get prefix length according to "*"
						int prefixLength = expected.indexOf('*');
						if (prefixLength >= 0 && prefixLength < actual.length()) {

							// reduce to prefixes
							expected = expected.substring(0, prefixLength);
							actual = actual.substring(0, prefixLength);
						}

						// handle case like rt=[Type1 Type2]
						if (actual.indexOf(" ") > -1) { // if contains white
														// space
							String[] parts = actual.split(" ");
							for (String part : parts) { // check each part for
														// match
								if (part.equals(expected)) {
									return true;
								}
							}
						}

						// compare strings
						if (expected.equals(actual)) {
							return true;
						}
					}
				}
			} else {
				// flag attribute
				if (attributes.getAttributeValues(s).size() > 0) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Fixed matches method
	 * 
	 * @param resource
	 * @param queries
	 * @return
	 */
	private static boolean matchesFixed(Resource resource, List<String> queries) {

		if (resource == null)
			return false;
		if (queries == null || queries.size() == 0)
			return true;

		ResourceAttributes attributes = resource.getAttributes();
		String path = resource.getPath() + resource.getName();

		for (String s : queries) {
			int delim = s.indexOf("=");
			if (delim != -1) {

				// split name-value-pair
				String attrName = s.substring(0, delim);
				String expected = s.substring(delim + 1);
				if (attrName.equals(LinkFormat.LINK)) {
					if (expected.endsWith("*")) {
						if (!path.startsWith(expected.substring(0, expected.length() - 1)))
							return false;
					} else {
						if (!path.equals(expected))
							return false;
					}
				} else if (attributes.containsAttribute(attrName)) {
					// lookup attribute value
					for (String actual : attributes.getAttributeValues(attrName)) {

						// get prefix length according to "*"
						int prefixLength = expected.indexOf('*');
						if (prefixLength >= 0 && prefixLength < actual.length()) {

							// reduce to prefixes
							expected = expected.substring(0, prefixLength);
							actual = actual.substring(0, prefixLength);
						}

						// handle case like rt=[Type1 Type2]
						if (actual.indexOf(" ") > -1) { // if contains white
														// space
							String[] parts = actual.split(" ");
							for (String part : parts) { // check each part for
														// match
								if (!part.equals(expected)) {
									return false;
								}
							}
						}

						// compare strings
						if (!expected.equals(actual)) {
							return false;
						}
					}
				} else if (!attributes.containsAttribute(attrName)) {
					return false;
				}
			} else {
				// flag attribute
				if (attributes.getAttributeValues(s).size() > 0) {
					return true;
				}
			}
		}
		return true;
	}

}
