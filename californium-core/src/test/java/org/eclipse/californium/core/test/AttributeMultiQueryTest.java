package org.eclipse.californium.core.test;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.server.resources.DiscoveryResource;
import org.eclipse.californium.core.server.resources.Resource;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class AttributeMultiQueryTest {
    private Resource root;

    @Before
    public void setup() {
        try {
            System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
            EndpointManager.clear();

            root = new CoapResource("");
            Resource sensors = new CoapResource("sensors");
            Resource temp = new CoapResource("temp");
            Resource light = new CoapResource("light");
            root.add(sensors);
            sensors.add(temp);
            sensors.add(light);

            sensors.getAttributes().setTitle("Sensor Index");
            temp.getAttributes().addResourceType("temperature-c");
            temp.getAttributes().addInterfaceDescription("sensor");
            temp.getAttributes().addAttribute("foo");
            temp.getAttributes().addAttribute("bar", "one");
            temp.getAttributes().addAttribute("bar", "two");

            light.getAttributes().addResourceType("light-lux");
            light.getAttributes().addInterfaceDescription("sensor");
            light.getAttributes().addAttribute("foo");
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    private void testFiltering(String query, String expected) {
        Request request = Request.newGet();
        request.setURI("/.well-known/core?" + query);

        DiscoveryResource discovery = new DiscoveryResource(root);
        String serialized = discovery.discoverTree(root, request.getOptions().getUriQuery());
        System.out.println(serialized);

        Assert.assertEquals(expected, serialized);
    }

    @Test
    public void testComplexMultiValueFiltering() {
        // bar=one and if=sensor should return only /sensors/temp.
        testFiltering("bar=one&if=sensor","</sensors/temp>;bar=\"one two\";foo;if=\"sensor\";rt=\"temperature-c\"");
    }

    @Test
    public void testComplexFlagAttributeFiltering() {
        testFiltering("bar=one&foo",
                "</sensors/temp>;bar=\"one two\";foo;if=\"sensor\";rt=\"temperature-c\"");
    }


    @Test
    public void testComplexMultiValueFilteringReversed() {
        // bar=one and if=sensor should return only /sensors/temp.
        testFiltering("if=sensor&bar=one","</sensors/temp>;bar=\"one two\";foo;if=\"sensor\";rt=\"temperature-c\"");
    }

    @Test
    public void testComplexFlagAttributeFilteringReversed() {
        // bar=one and foo should return only /sensors/temp
        testFiltering("foo&bar=one",
                "</sensors/temp>;bar=\"one two\";foo;if=\"sensor\";rt=\"temperature-c\"");
    }

    @Test
    public void testMultipleSameAttributeFiltering() {
        // bar=one and bar=two should match /sensors/temp
        testFiltering("bar=one&bar=two",
                "</sensors/temp>;bar=\"one two\";foo;if=\"sensor\";rt=\"temperature-c\"");
        // bar=one and bar=three should match nothing.
        testFiltering("bar=one&bar=three",
                "");
    }
}
