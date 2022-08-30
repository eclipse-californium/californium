/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_CBOR;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_XML;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Arrays;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.server.resources.ResourceAttributes;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Unit test cases validating behavior of the {@link LinkFormat} class.
 *
 */
@Category(Small.class)
public class LinkFormatTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	@Test
	public void testSerializeResource() {
		CoapResource node = new CoapResource("node");
		node.add(new CoapResource("child1"));
		CoapResource child = new CoapResource("child2");
		node.add(child);
		node.add(new CoapResource("child3"));
		child.add(new CoapResource("grandchild"));

		String tree = LinkFormat.serializeTree(node);
		assertThat(tree, containsString("<node/child1>"));
		assertThat(tree, containsString("<node/child2>"));
		assertThat(tree, containsString("<node/child2/grandchild>"));

	}

	@Test
	public void testSerializeLinks() {
		CoapResource node = new CoapResource("node");
		node.add(new CoapResource("child1"));
		CoapResource child = new CoapResource("child2");
		node.add(child);
		node.add(new CoapResource("child3"));
		child.add(new CoapResource("grandchild"));

		Set<WebLink> subTree = LinkFormat.getSubTree(node);
		String tree = LinkFormat.serialize(subTree);
		assertThat(tree, not(containsString("<node>")));
		assertThat(tree, containsString("<node/child1>"));
		assertThat(tree, containsString("<node/child2>"));
		assertThat(tree, containsString("<node/child2/grandchild>"));
		assertThat(tree, containsString("<node/child3>"));

		subTree = LinkFormat.getTree(node);
		tree = LinkFormat.serialize(subTree);
		assertThat(tree, containsString("<node>"));
		assertThat(tree, containsString("<node/child1>"));
		assertThat(tree, containsString("<node/child2>"));
		assertThat(tree, containsString("<node/child2/grandchild>"));
		assertThat(tree, containsString("<node/child3>"));

		WebLink webLink = LinkFormat.createWebLink(child);
		tree = LinkFormat.serialize(webLink);
		assertThat(tree, is("<node/child2>"));
	}

	@Test
	public void testSerializeResourceWithAttributes() {
		CoapResource node = new CoapResource("node");
		CoapResource child = new CoapResource("child");
		child.getAttributes().setTitle("Children of the Node");
		child.getAttributes().setMaximumSizeEstimate(4096);
		child.getAttributes().setObservable();
		child.getAttributes().addContentType(TEXT_PLAIN);
		child.getAttributes().addContentType(APPLICATION_JSON);
		child.getAttributes().addContentType(APPLICATION_XML);
		child.getAttributes().addResourceType("test");
		node.add(child);
		node.add(new CoapResource("next"));

		String tree = LinkFormat.serializeTree(node);
		assertThat(tree, containsString("<node/child>"));
		assertThat(tree, containsString(";ct=\"0 50 41\""));
		assertThat(tree, containsString(";rt=\"test\""));
		assertThat(tree, containsString(";sz=4096"));
		assertThat(tree, containsString(";title=\"Children of the Node\""));
	}

	@Test
	public void testSerializeWebLinksWithAttributes() {
		CoapResource node = new CoapResource("node");
		CoapResource child = new CoapResource("child");
		child.getAttributes().setTitle("Children of the Node");
		child.getAttributes().setMaximumSizeEstimate(4096);
		child.getAttributes().setObservable();
		child.getAttributes().addContentType(TEXT_PLAIN);
		child.getAttributes().addContentType(APPLICATION_JSON);
		child.getAttributes().addContentType(APPLICATION_XML);
		child.getAttributes().addResourceType("test");
		node.add(child);
		node.add(new CoapResource("next"));

		Set<WebLink> subTree = LinkFormat.getSubTree(node);
		String tree = LinkFormat.serialize(subTree);
		assertThat(tree, containsString("<node/child>"));
		assertThat(tree, containsString(";ct=\"0 50 41\""));
		assertThat(tree, containsString(";rt=\"test\""));
		assertThat(tree, containsString(";sz=4096"));
		assertThat(tree, containsString(";title=\"Children of the Node\""));

		WebLink webLink = LinkFormat.createWebLink(child);
		tree = LinkFormat.serialize(webLink);
		assertThat(tree, containsString("<node/child>"));
		assertThat(tree, containsString(";ct=\"0 50 41\""));
		assertThat(tree, containsString(";rt=\"test\""));
		assertThat(tree, containsString(";sz=4096"));
		assertThat(tree, containsString(";title=\"Children of the Node\""));
	}

	@Test
	public void testParse() {
		String tree = "<node/child2>,<node/child2/grandchild>,<node/child3>,<node/child1>";

		Set<WebLink> links = LinkFormat.parse(tree);
		assertThat(WebLink.findByUri(links, "node/child1"), is(notNullValue()));
		assertThat(WebLink.findByUri(links, "node/child2"), is(notNullValue()));
		assertThat(WebLink.findByUri(links, "node/child2/grandchild"), is(notNullValue()));
		assertThat(WebLink.findByUri(links, "node"), is(nullValue()));
	}

	@Test
	public void testParseWithAttributes() {
		String tree = "<node/child>;ct=\"0 50 41\";obs;rt=\"test\";sz=4096;title=\"Children of the Node\",<node/next>";

		Set<WebLink> links = LinkFormat.parse(tree);
		assertThat(WebLink.findByUri(links, "node"), is(nullValue()));
		WebLink link = WebLink.findByUri(links, "node/child");
		assertThat(link, is(notNullValue()));
		ResourceAttributes attributes = link.getAttributes();
		assertThat(attributes.getTitle(), is("Children of the Node"));
		assertThat(attributes.getMaximumSizeEstimate(), is("4096"));
		assertThat(attributes.getResourceTypes(), hasItem("test"));
		assertThat(attributes.getContentTypes(), hasItem("0"));
		assertThat(attributes.getContentTypes(), hasItem("50"));
		assertThat(attributes.getContentTypes(), hasItem("41"));
	}

	@Test
	public void testSerializeResourceWithMatchingLink() {
		CoapResource node = new CoapResource("node");
		CoapResource child = new CoapResource("child1");
		child.getAttributes().setTitle("Children of the Node");
		child.getAttributes().setMaximumSizeEstimate(4096);
		child.getAttributes().setObservable();
		child.getAttributes().addContentType(TEXT_PLAIN);
		child.getAttributes().addContentType(APPLICATION_XML);
		child.getAttributes().addResourceType("test-in");
		node.add(child);
		child = new CoapResource("child2");
		child.getAttributes().setTitle("Children of the Node");
		child.getAttributes().addContentType(TEXT_PLAIN);
		child.getAttributes().addContentType(APPLICATION_JSON);
		child.getAttributes().addResourceType("test-out");
		node.add(child);

		// wildcard
		String tree = LinkFormat.serializeTree(node, Arrays.asList("rt=test*"));
		assertThat(tree, containsString("<node/child1>"));
		assertThat(tree, containsString("<node/child2>"));

		tree = LinkFormat.serializeTree(node, Arrays.asList("rt=test"));
		assertThat(tree, is(""));

		tree = LinkFormat.serializeTree(node, Arrays.asList("rt=test-in"));
		assertThat(tree, containsString("<node/child1>"));
		assertThat(tree, not(containsString("<node/child2>")));

		// * not at the end => no wildcard
		tree = LinkFormat.serializeTree(node, Arrays.asList("rt=te*t-in"));
		assertThat(tree, is(""));

		tree = LinkFormat.serializeTree(node, Arrays.asList("href=node/child2"));
		assertThat(tree, not(containsString("<node/child1>")));
		assertThat(tree, containsString("<node/child2>"));

		tree = LinkFormat.serializeTree(node, Arrays.asList("href=node/child*"));
		assertThat(tree, containsString("<node/child1>"));
		assertThat(tree, containsString("<node/child2>"));

		tree = LinkFormat.serializeTree(node, Arrays.asList("ct=" + APPLICATION_XML));
		assertThat(tree, containsString("<node/child1>"));
		assertThat(tree, not(containsString("<node/child2>")));

		tree = LinkFormat.serializeTree(node, Arrays.asList("ct=" + TEXT_PLAIN));
		assertThat(tree, containsString("<node/child1>"));
		assertThat(tree, containsString("<node/child2>"));

		tree = LinkFormat.serializeTree(node, Arrays.asList("ct=" + APPLICATION_CBOR));
		assertThat(tree, is(""));
	}

	@Test
	public void testSerializeWebLinkWithMatchingLink() {
		CoapResource node = new CoapResource("node");
		CoapResource child = new CoapResource("child1");
		child.getAttributes().setTitle("Children of the Node");
		child.getAttributes().setMaximumSizeEstimate(4096);
		child.getAttributes().setObservable();
		child.getAttributes().addContentType(TEXT_PLAIN);
		child.getAttributes().addContentType(APPLICATION_XML);
		child.getAttributes().addResourceType("test-in");
		node.add(child);
		child = new CoapResource("child2");
		child.getAttributes().setTitle("Children of the Node");
		child.getAttributes().addContentType(TEXT_PLAIN);
		child.getAttributes().addContentType(APPLICATION_JSON);
		child.getAttributes().addResourceType("test-out");
		node.add(child);
		child = new CoapResource("child3");
		child.getAttributes().setTitle("Children of the Node");
		node.add(child);

		// wildcard
		Set<WebLink> links = LinkFormat.getSubTree(node, Arrays.asList("rt=test*"));
		assertThat(WebLink.findByUri(links, "node/child1"), is(notNullValue()));
		assertThat(WebLink.findByUri(links, "node/child2"), is(notNullValue()));
		assertThat(WebLink.findByUri(links, "node/child3"), is(nullValue()));

		String tree = LinkFormat.serialize(links);
		assertThat(tree, containsString("<node/child1>"));
		assertThat(tree, containsString("<node/child2>"));
		assertThat(tree, not(containsString("<node/child3>")));

		links = LinkFormat.getSubTree(node, Arrays.asList("rt=test"));
		assertThat(links.isEmpty(), is(true));
		tree = LinkFormat.serialize(links);
		assertThat(tree, is(""));

		links = LinkFormat.getSubTree(node, Arrays.asList("rt=test-in"));
		assertThat(WebLink.findByUri(links, "node/child1"), is(notNullValue()));
		assertThat(WebLink.findByUri(links, "node/child2"), is(nullValue()));
		assertThat(WebLink.findByUri(links, "node/child3"), is(nullValue()));

		// * not at the end => no wildcard
		links = LinkFormat.getSubTree(node, Arrays.asList("rt=te*t-in"));
		assertThat(links.isEmpty(), is(true));

		links = LinkFormat.getSubTree(node, Arrays.asList("href=node/child2"));
		assertThat(WebLink.findByUri(links, "node/child1"), is(nullValue()));
		assertThat(WebLink.findByUri(links, "node/child2"), is(notNullValue()));
		assertThat(WebLink.findByUri(links, "node/child3"), is(nullValue()));

		links = LinkFormat.getSubTree(node, Arrays.asList("href=node/child*"));
		assertThat(WebLink.findByUri(links, "node/child1"), is(notNullValue()));
		assertThat(WebLink.findByUri(links, "node/child2"), is(notNullValue()));
		assertThat(WebLink.findByUri(links, "node/child3"), is(notNullValue()));

		links = LinkFormat.getSubTree(node, Arrays.asList("ct=" + APPLICATION_XML));
		assertThat(WebLink.findByUri(links, "node/child1"), is(notNullValue()));
		assertThat(WebLink.findByUri(links, "node/child2"), is(nullValue()));
		assertThat(WebLink.findByUri(links, "node/child3"), is(nullValue()));

		links = LinkFormat.getSubTree(node, Arrays.asList("ct=" + TEXT_PLAIN));
		assertThat(WebLink.findByUri(links, "node/child1"), is(notNullValue()));
		assertThat(WebLink.findByUri(links, "node/child2"), is(notNullValue()));
		assertThat(WebLink.findByUri(links, "node/child3"), is(nullValue()));

		links = LinkFormat.getSubTree(node, Arrays.asList("ct=" + APPLICATION_CBOR));
		assertThat(links.isEmpty(), is(true));
	}

}
