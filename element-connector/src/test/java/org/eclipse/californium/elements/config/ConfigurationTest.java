/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.config;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.Configuration.ModuleDefinitionsProvider;
import org.eclipse.californium.elements.rule.LoggingRule;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.junit.Rule;
import org.junit.Test;

/**
 * Unit tests for {@link Configuration}.
 * 
 * @since 3.0
 */
public class ConfigurationTest {

	private enum TestValues {
		TEST1, TEST2, TEST3, TEST4, TEST5
	}

	private static final String MODULE = "TEST.";
	private static final IntegerDefinition INT = new IntegerDefinition(MODULE + "INT", "TEST");
	private static final IntegerDefinition INT0 = new IntegerDefinition(MODULE + "INT0", "TEST", 0);
	private static final BooleanDefinition BOOL = new BooleanDefinition(MODULE + "BOOL", "TEST");
	private static final BooleanDefinition BOOL0 = new BooleanDefinition(MODULE + "BOOL0", "TEST", false);
	private static final BooleanDefinition BOOL1 = new BooleanDefinition(MODULE + "BOOL1", "TEST", true);

	private static final ModuleDefinitionsProvider DEFAULTS = new ModuleDefinitionsProvider() {

		@Override
		public String getModule() {
			return MODULE;
		}

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(INT, 10);
			config.set(INT0, null);
			config.set(BOOL, true);
			config.set(BOOL0, null);
			config.set(BOOL1, null);
		}
	};

	private static final String MODULE2 = "TEST2.";
	private static final IntegerDefinition INT2 = new IntegerDefinition(MODULE2 + "INT2", "TEST", null, 1);
	private static final StringDefinition STRING = new StringDefinition(MODULE2 + "STRING", "TEST");

	private static final ModuleDefinitionsProvider DEFAULTS2 = new ModuleDefinitionsProvider() {

		@Override
		public String getModule() {
			return MODULE2;
		}

		@Override
		public void applyDefinitions(Configuration config) {
			TcpConfig.register();
			config.set(INT2, 100);
			config.set(STRING, "Hallo");
		}
	};

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	@Rule 
	public LoggingRule logging = new LoggingRule();

	@Test
	public void testConfigurationAddModule() {
		Configuration.addDefaultModule(DEFAULTS);
		Configuration configuration = Configuration.createStandardWithoutFile();
		// assert default values
		assertThat(configuration.get(INT), is(10));
		assertThat(configuration.get(INT0), is(0));
		assertThat(configuration.get(BOOL), is(true));
		assertThat(configuration.get(BOOL0), is(false));
	}

	@Test
	public void testConfigurationCustomModule() {
		logging.setLoggingLevel("ERROR", Configuration.class);
		Configuration.addDefaultModule(DEFAULTS);
		Configuration configuration = Configuration.createStandardWithoutFile();
		configuration.set(STRING, "bye!");
		configuration = reload(configuration, DEFAULTS2);
		// assert default value
		assertThat(configuration.get(INT2), is(100));
		// assert overwritten value
		assertThat(configuration.get(STRING), is("bye!"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConfigurationAddModuleNull() {
		Configuration.addDefaultModule(new ModuleDefinitionsProvider() {

			@Override
			public String getModule() {
				return null;
			}

			@Override
			public void applyDefinitions(Configuration config) {
			}
		});
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConfigurationAddModuleEmpty() {
		Configuration.addDefaultModule(new ModuleDefinitionsProvider() {

			@Override
			public String getModule() {
				return "";
			}

			@Override
			public void applyDefinitions(Configuration config) {
			}
		});
	}

	@Test(expected = NullPointerException.class)
	public void testConfigurationAddModuleNull2() {
		Configuration.addDefaultModule(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConfigurationAddModuleTwice() {
		Configuration.addDefaultModule(new ModuleDefinitionsProvider() {

			@Override
			public String getModule() {
				return "DOUBLE";
			}

			@Override
			public void applyDefinitions(Configuration config) {
			}
		});
		Configuration.addDefaultModule(new ModuleDefinitionsProvider() {

			@Override
			public String getModule() {
				return "DOUBLE";
			}

			@Override
			public void applyDefinitions(Configuration config) {
			}
		});
	}

	@Test
	public void testConfigurationBoolean() {
		Configuration configuration = Configuration.createStandardWithoutFile();
		configuration.set(BOOL, true);
		assertThat(configuration.get(BOOL), is(true));
		configuration.set(BOOL, false);
		assertThat(configuration.get(BOOL), is(false));
		configuration.set(BOOL, null);
		assertThat(configuration.get(BOOL), is(nullValue()));
		configuration.set(BOOL0, true);
		assertThat(configuration.get(BOOL0), is(true));
		configuration.set(BOOL0, false);
		assertThat(configuration.get(BOOL0), is(false));
		configuration.set(BOOL0, null);
		assertThat(configuration.get(BOOL0), is(false));
		configuration.set(BOOL1, true);
		assertThat(configuration.get(BOOL1), is(true));
		configuration.set(BOOL1, false);
		assertThat(configuration.get(BOOL1), is(false));
		configuration.set(BOOL1, null);
		assertThat(configuration.get(BOOL1), is(true));
	}

	@Test
	public void testConfigurationUnknownBoolean() {
		Configuration configuration = Configuration.createStandardWithoutFile();
		BooleanDefinition BOOL_DEF = new BooleanDefinition(MODULE + "BOOL_DEF", "TEST", true);
		assertThat(configuration.get(BOOL_DEF), is(true));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConfigurationInvalidInteger() {
		Configuration configuration = Configuration.createStandardWithoutFile();
		configuration.set(INT2, 0);
	}

	@Test
	public void testConfigurationEnum() {
		EnumDefinition<TestValues> enumDefinition = new EnumDefinition<>(MODULE2 + "ENUM", "Test Enum",
				TestValues.values());
		Configuration configuration = Configuration.createStandardWithoutFile();
		configuration.set(enumDefinition, TestValues.TEST2);
		configuration = reload(configuration, null);
		assertThat(configuration.get(enumDefinition), is(TestValues.TEST2));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConfigurationEnumFailure() {
		EnumDefinition<TestValues> enumDefinition = new EnumDefinition<>(MODULE2 + "ENUM2", "Test Enum",
				TestValues.TEST1, TestValues.TEST2);
		Configuration configuration = Configuration.createStandardWithoutFile();
		configuration.set(enumDefinition, TestValues.TEST3);
	}

	@Test
	public void testConfigurationEnumList() {
		EnumListDefinition<TestValues> enumDefinition = new EnumListDefinition<>(MODULE2 + "ENUM3", "Test Enum List",
				TestValues.values());
		Configuration configuration = Configuration.createStandardWithoutFile();
		configuration.setAsList(enumDefinition, TestValues.TEST2, TestValues.TEST4);
		configuration = reload(configuration, null);
		assertThat(configuration.get(enumDefinition), hasItem(TestValues.TEST2));
		assertThat(configuration.get(enumDefinition), hasItem(TestValues.TEST4));
		assertThat(configuration.get(enumDefinition), not(hasItem(TestValues.TEST3)));

		configuration.setAsList(enumDefinition, TestValues.TEST5);
		configuration = reload(configuration, null);
		assertThat(configuration.get(enumDefinition), hasItem(TestValues.TEST5));
		assertThat(configuration.get(enumDefinition), not(hasItem(TestValues.TEST3)));

		List<TestValues> values = Arrays.asList(TestValues.TEST1, TestValues.TEST3, TestValues.TEST4);
		configuration.set(enumDefinition, values);
		List<TestValues> storedValues = configuration.get(enumDefinition);
		try {
			storedValues.add(TestValues.TEST2);
			fail("List is not unmodifiable!");
		} catch (UnsupportedOperationException ex) {
		}

		configuration = reload(configuration, null);
		assertThat(configuration.get(enumDefinition), hasItem(TestValues.TEST1));
		assertThat(configuration.get(enumDefinition), hasItem(TestValues.TEST3));
		assertThat(configuration.get(enumDefinition), hasItem(TestValues.TEST4));
		assertThat(configuration.get(enumDefinition), not(hasItem(TestValues.TEST5)));

		configuration.set(enumDefinition, null);
		configuration = reload(configuration, null);
		assertThat(configuration.get(enumDefinition), is(nullValue()));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConfigurationEnumListWithEmptyListFailure() {
		EnumListDefinition<TestValues> enumDefinition = new EnumListDefinition<>(MODULE2 + "ENUM4", "Test Enum List",
				null, 1, TestValues.values());
		Configuration configuration = Configuration.createStandardWithoutFile();
		configuration.setAsList(enumDefinition);
	}

	@Test
	public void testConfigurationEnumListAsText() {
		EnumListDefinition<TestValues> enumDefinition = new EnumListDefinition<>(MODULE2 + "ENUM5", "Test Enum List",
				null, 0, TestValues.values());
		Configuration configuration = Configuration.createStandardWithoutFile();
		configuration.setAsListFromText(enumDefinition);
		List<TestValues> list = configuration.get(enumDefinition);
		assertThat(list.isEmpty(), is(true));
		configuration.setAsListFromText(enumDefinition, "TEST1", "TEST4");
		list = configuration.get(enumDefinition);
		assertThat(list.size(), is(2));
		assertThat(configuration.get(enumDefinition), hasItem(TestValues.TEST1));
		assertThat(configuration.get(enumDefinition), hasItem(TestValues.TEST4));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConfigurationEnumListAsTextWithFailure() {
		EnumListDefinition<TestValues> enumDefinition = new EnumListDefinition<>(MODULE2 + "ENUM6", "Test Enum List",
				null, 0, TestValues.values());
		Configuration configuration = Configuration.createStandardWithoutFile();
		configuration.setAsListFromText(enumDefinition, "TEST1", "TESTx");
	}

	@Test
	public void testConfigurationStringSet() {
		StringSetDefinition setDefinition = new StringSetDefinition(MODULE2 + "STRING_SET", "Test String-Set", "val1",
				"val2");
		Configuration configuration = Configuration.createStandardWithoutFile();
		configuration.set(setDefinition, "val1");
		configuration = reload(configuration, null);
		assertThat(configuration.get(setDefinition), is("val1"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConfigurationStringSetFailure() {
		StringSetDefinition setDefinition = new StringSetDefinition(MODULE2 + "STRING_SET2", "Test String-Set", "val1",
				"val2");
		Configuration configuration = Configuration.createStandardWithoutFile();
		configuration.set(setDefinition, "val3");
	}

	@Test
	public void testConfigurationStringSetDefault() {
		StringSetDefinition setDefinition = new StringSetDefinition(MODULE2 + "STRING_SET3", "Test String-Set", "val2",
				"val1", "val2");
		Configuration configuration = Configuration.createStandardWithoutFile();
		configuration.set(setDefinition, null);
		configuration = reload(configuration, null);
		assertThat(configuration.get(setDefinition), is("val2"));
	}

	@Test
	public void testConfigurationTime() {
		TimeDefinition timeDefinition = new TimeDefinition(MODULE2 + "TIME", "Test Time");
		Configuration configuration = Configuration.createStandardWithoutFile();
		configuration.set(timeDefinition, 10, TimeUnit.SECONDS);
		configuration = reload(configuration, null);
		assertThat(configuration.get(timeDefinition, TimeUnit.MILLISECONDS), is(10000L));
	}

	@Test
	public void testConfigurationTransientTime() {
		TimeDefinition timeDefinition = new TimeDefinition(MODULE2 + "TIME_TRANSIENT", "Test Time");
		Configuration configuration = Configuration.createStandardWithoutFile();
		configuration.set(timeDefinition, 10, TimeUnit.SECONDS);
		configuration.setTransient(timeDefinition);
		configuration = reload(configuration, null);
		assertThat(configuration.get(timeDefinition, TimeUnit.MILLISECONDS), is(nullValue()));
	}

	private static Configuration reload(Configuration configuration, DefinitionsProvider provider) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		configuration.store(out, "Test Values", "Test");
		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		return Configuration.createFromStream(in, provider);
	}
}
