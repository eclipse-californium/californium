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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Helper for processing URI-query parameters.
 * <p>
 * The API is intended to provide strict query-parameter checks for error
 * responses.
 * </p>
 * 
 * <pre>
 * try {
 * 	UriQueryParameter helper = request.getOptions().getUriQueryParameter(SUPPORTED);
 * 	// mandatory
 * 	resource = helper.getArgument(URI_QUERY_OPTION_RESOURCE);
 * 	// optional
 * 	language = helper.getArgument(URI_QUERY_OPTION_LANG, null);
 * } catch (IllegalArgumentException ex) {
 * 	respond(BAD_OPTION, ex.getMessage(), MediaTypeRegistry.UNDEFINED);
 * }
 * </pre>
 * 
 * <p>
 * Using one of {@link #getArgument(String)},
 * {@link #getArgumentAsInteger(String)} or {@link #getArgumentAsLong(String)}
 * getters without default fails with a {@link IllegalArgumentException}, if the
 * query parameter is not available or has no argument. These are used for
 * mandatory parameters.
 * </p>
 * 
 * <p>
 * Using {@link #hasParameter(String)} or a getter with default value don't
 * fail, if the parameter or value is missing, therefore these are used for
 * optional parameters.
 * </p>
 * 
 * @since 3.2
 */
public class UriQueryParameter {

	/**
	 * Empty Uri query parameter
	 * 
	 * @since 3.8
	 */
	public static final UriQueryParameter EMPTY = new UriQueryParameter();

	/**
	 * Map of parameter names and arguments.
	 * 
	 * Parameter without arguments are stored with {@code null} as argument.
	 */
	private final Map<String, String> parameterMap = new HashMap<>();

	/**
	 * Empty parameter.
	 * 
	 * Use {@link #EMPTY}.
	 * 
	 * @since 3.8
	 */
	private UriQueryParameter() {
	}

	/**
	 * Create query parameter using all provided query parameter.
	 * 
	 * @param queryOptions list of query parameter.
	 */
	public UriQueryParameter(List<String> queryOptions) {
		this(queryOptions, null, null);
	}

	/**
	 * Create query parameter using all provided query parameter and verify the
	 * parameter with the list of supported parameters.
	 * 
	 * @param queryParameter list of query parameter.
	 * @param supportedParameterNames list of supported parameter names. May be
	 *            {@code null} or empty, if the parameter names should not be
	 *            verified.
	 * @throws IllegalArgumentException if a provided query parameter could not
	 *             be verified.
	 */
	public UriQueryParameter(List<String> queryParameter, List<String> supportedParameterNames) {
		this(queryParameter, supportedParameterNames, null);
	}

	/**
	 * Create query parameter using all provided and verified query parameter.
	 * 
	 * Query parameter, which could not be verified successful are added to the
	 * list of unsupported parameter.
	 * 
	 * @param queryParameter list of query parameter.
	 * @param supportedParameterNames list of supported parameter names. May be
	 *            {@code null} or empty, if the parameter names should not be
	 *            verified.
	 * @param unsupportedParameter list to add the unsupported parameter. May be
	 *            {@code null}, if unsupported parameter names should cause a
	 *            {@link IllegalArgumentException}.
	 * @throws IllegalArgumentException if a provided query parameter could not
	 *             be verified and no list for unsupported parameter is
	 *             provided.
	 */
	public UriQueryParameter(List<String> queryParameter, List<String> supportedParameterNames,
			List<String> unsupportedParameter) {
		for (String parameter : queryParameter) {
			String name = parameter;
			String value = null;
			int index = name.indexOf('=');
			if (index >= 0) {
				name = parameter.substring(0, index);
				if (parameter.length() > index + 1) {
					value = parameter.substring(index + 1);
				} else {
					value = "";
				}
			}
			if (supportedParameterNames != null && !supportedParameterNames.isEmpty()
					&& !supportedParameterNames.contains(name)) {
				if (unsupportedParameter != null) {
					unsupportedParameter.add(parameter);
				} else {
					throw new IllegalArgumentException("URI-query-option '" + parameter + "' is not supported!");
				}
			} else {
				parameterMap.put(name, value);
			}
		}
	}

	/**
	 * Number of query parameter.
	 * 
	 * @return number of query parameter.
	 */
	public int size() {
		return parameterMap.size();
	}

	/**
	 * Check, if query parameter with provided name is available.
	 * 
	 * @param name parameter name to check
	 * @return {@code true}, if available, {@code false}, otherwise.
	 */
	public boolean hasParameter(String name) {
		return parameterMap.containsKey(name);
	}

	/**
	 * Get parameter argument for provided parameter name.
	 * 
	 * @param name parameter name.
	 * @return parameter argument
	 * @throws IllegalArgumentException if parameter is not available or has no
	 *             argument
	 */
	public String getArgument(String name) {
		if (!hasParameter(name)) {
			throw new IllegalArgumentException("Missing parameter '" + name + "' in URI-query-options!");
		}
		String value = parameterMap.get(name);
		if (value == null) {
			throw new IllegalArgumentException("Missing argument for URI-query-option '" + name + "'!");
		}
		return value;
	}

	/**
	 * Get parameter argument for provided parameter name with default.
	 * 
	 * @param name parameter name
	 * @param def default argument, if parameter is missing or has no argument
	 * @return parameter argument
	 */
	public String getArgument(String name, String def) {
		String value = parameterMap.get(name);
		if (value == null) {
			value = def;
		}
		return value;
	}

	/**
	 * Get value as integer.
	 * 
	 * @param name name of parameter
	 * @param value value of parameter
	 * @return value as integer
	 * @throws IllegalArgumentException if value is no integer number
	 */
	private int getValueAsInteger(String name, String value) {
		try {
			return Integer.parseInt(value);
		} catch (NumberFormatException ex) {
			throw new IllegalArgumentException("URI-query-option '" + name + "=" + value + "' is no number!");
		}
	}

	/**
	 * Get parameter argument as integer for provided parameter name.
	 * 
	 * @param name parameter name.
	 * @return parameter argument as integer
	 * @throws IllegalArgumentException if parameter is not available, has no
	 *             argument, or the argument is no integer number
	 */
	public int getArgumentAsInteger(String name) {
		String value = getArgument(name);
		return getValueAsInteger(name, value);
	}

	/**
	 * Get parameter argument as integer for provided parameter name with
	 * default.
	 * 
	 * @param name parameter name.
	 * @param def default value
	 * @return parameter argument as integer
	 * @throws IllegalArgumentException if the argument is no integer number
	 */
	public int getArgumentAsInteger(String name, int def) {
		String value = parameterMap.get(name);
		if (value != null) {
			return getValueAsInteger(name, value);
		} else {
			return def;
		}
	}

	/**
	 * Get parameter argument as integer for provided parameter name with
	 * default and minimum value.
	 * 
	 * @param name parameter name.
	 * @param def default value
	 * @param min minimum value
	 * @return parameter argument as integer
	 * @throws IllegalArgumentException if the argument is no integer number or
	 *             smaller that the minimum
	 */
	public int getArgumentAsInteger(String name, int def, int min) {
		int result = getArgumentAsInteger(name, def);
		if (result < min) {
			throw new IllegalArgumentException(
					"URI-query-option '" + name + "=" + result + "' is less than " + min + "!");
		}
		return result;
	}

	/**
	 * Get parameter argument as integer for provided parameter name with
	 * default, minimum value and maximum value.
	 * 
	 * @param name parameter name.
	 * @param def default value
	 * @param min minimum value
	 * @param max maximum value
	 * @return parameter argument as integer
	 * @throws IllegalArgumentException if the argument is no integer number,
	 *             smaller that the minimum, or larger than the maximum. Or the
	 *             maximum is less than the minimum.
	 */
	public int getArgumentAsInteger(String name, int def, int min, int max) {
		if (min > max) {
			throw new IllegalArgumentException("Max. " + max + " is less then min. " + min + "!");
		}
		int result = getArgumentAsInteger(name, def, min);
		if (max < result) {
			throw new IllegalArgumentException(
					"URI-query-option '" + name + "=" + result + "' is more than " + max + "!");
		}
		return result;
	}

	/**
	 * Get value as long integer.
	 * 
	 * @param name name of parameter
	 * @param value value of parameter
	 * @return value as long integer
	 * @throws IllegalArgumentException if value is no long integer number
	 */
	private long getValueAsLong(String name, String value) {
		try {
			return Long.parseLong(value);
		} catch (NumberFormatException ex) {
			throw new IllegalArgumentException("URI-query-option '" + name + "=" + value + "' is no number!");
		}
	}

	/**
	 * Get parameter argument as long integer for provided parameter name.
	 * 
	 * @param name parameter name.
	 * @return parameter argument as long integer
	 * @throws IllegalArgumentException if parameter is not available, has no
	 *             argument, or the argument is no long integer number
	 */
	public long getArgumentAsLong(String name) {
		String value = getArgument(name);
		return getValueAsLong(name, value);
	}

	/**
	 * Get parameter argument as long integer for provided parameter name with
	 * default.
	 * 
	 * @param name parameter name.
	 * @param def default value
	 * @return parameter argument as long integer
	 * @throws IllegalArgumentException if the argument is no long integer
	 *             number
	 */
	public long getArgumentAsLong(String name, long def) {
		String value = parameterMap.get(name);
		if (value != null) {
			return getValueAsLong(name, value);
		} else {
			return def;
		}
	}

	/**
	 * Get parameter argument as long integer for provided parameter name with
	 * default and minimum value.
	 * 
	 * @param name parameter name.
	 * @param def default value
	 * @param min minimum value
	 * @return parameter argument as long integer
	 * @throws IllegalArgumentException if the argument is no long integer
	 *             number or smaller that the minimum
	 */
	public long getArgumentAsLong(String name, long def, long min) {
		long result = getArgumentAsLong(name, def);
		if (result < min) {
			throw new IllegalArgumentException(
					"URI-query-option '" + name + "=" + result + "' is less than " + min + "!");
		}
		return result;
	}

	/**
	 * Get parameter argument as long integer for provided parameter name with
	 * default, minimum value and maximum value.
	 * 
	 * @param name parameter name.
	 * @param def default value
	 * @param min minimum value
	 * @param max maximum value
	 * @return parameter argument as long integer
	 * @throws IllegalArgumentException if the argument is no long integer
	 *             number, smaller that the minimum, or larger than the maximum.
	 *             Or the maximum is less than the minimum.
	 */
	public long getArgumentAsLong(String name, long def, long min, long max) {
		if (min > max) {
			throw new IllegalArgumentException("Max. " + max + " is less then min. " + min + "!");
		}
		long result = getArgumentAsLong(name, def, min);
		if (max < result) {
			throw new IllegalArgumentException(
					"URI-query-option '" + name + "=" + result + "' is more than " + max + "!");
		}
		return result;
	}

}
