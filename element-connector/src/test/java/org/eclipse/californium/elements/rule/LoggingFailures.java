/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.rule;

import org.eclipse.californium.elements.util.DirectDatagramSocketImpl;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

/**
 * Rule for logging messages only on failures.
 * 
 * Must be used with annotation "@Rule", "@ClassRule" will not work! Only
 * supported when using {@link DirectDatagramSocketImpl}.
 */
public class LoggingFailures implements TestRule {

	@Override
	public Statement apply(final Statement base, final Description description) {
		if (DirectDatagramSocketImpl.isEnabled()) {
			return new Statement() {

				@Override
				public void evaluate() throws Throwable {
					DirectDatagramSocketImpl.clearConditionalLog();
					try {
						base.evaluate();
					} catch (Throwable t) {
						DirectDatagramSocketImpl.conditionalLog();
						throw t;
					}
				}
			};
		} else {
			return base;
		}
	}
}
