/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *                                 skeleton derived from org.slf4j:slf4j-android
 ******************************************************************************/
package org.slf4j.impl;

import android.util.Log;

import org.slf4j.Marker;
import org.slf4j.helpers.FormattingTuple;
import org.slf4j.helpers.MessageFormatter;
import org.slf4j.spi.LocationAwareLogger;

import java.util.HashMap;
import java.util.Map;

/**
 * Logger implementation using android log as destination.
 * <p>
 * Provides appended location information and level mapping.
 */
public final class AndroidLoggerAdapter implements LocationAwareLogger {

    private final InternalConfiguration configuration;
    private final String name;

    // WARN: AndroidLoggerAdapter constructor should have only package access so
    // that only AndroidLoggerFactory be able to create one.
    AndroidLoggerAdapter(String name, Configuration configuration) {
        this.name = name;
        this.configuration = new InternalConfiguration(configuration);
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean isTraceEnabled() {
        return configuration.trace;
    }

    @Override
    public void trace(String msg) {
        if (isTraceEnabled()) {
            log(null, null, TRACE_INT, msg, null, null);
        }
    }

    @Override
    public void trace(String format, Object arg) {
        if (isTraceEnabled()) {
            log(null, null, TRACE_INT, format, new Object[]{arg}, null);
        }
    }

    @Override
    public void trace(String format, Object arg1, Object arg2) {
        if (isTraceEnabled()) {
            log(null, null, TRACE_INT, format, new Object[]{arg1, arg2}, null);
        }
    }

    @Override
    public void trace(String format, Object... argArray) {
        if (isTraceEnabled()) {
            log(null, null, TRACE_INT, format, argArray, null);
        }
    }

    @Override
    public void trace(String msg, Throwable t) {
        if (isTraceEnabled()) {
            log(null, null, TRACE_INT, msg, null, t);
        }
    }

    @Override
    public boolean isTraceEnabled(Marker marker) {
        return configuration.trace;
    }

    @Override
    public void trace(Marker marker, String msg) {
        if (isTraceEnabled(marker)) {
            log(marker, null, TRACE_INT, msg, null, null);
        }
    }

    @Override
    public void trace(Marker marker, String format, Object arg) {
        if (isTraceEnabled(marker)) {
            log(marker, null, TRACE_INT, format, new Object[]{arg}, null);
        }
    }

    @Override
    public void trace(Marker marker, String format, Object arg1, Object arg2) {
        if (isTraceEnabled(marker)) {
            log(marker, null, TRACE_INT, format, new Object[]{arg1, arg2}, null);
        }
    }

    @Override
    public void trace(Marker marker, String format, Object... argArray) {
        if (isTraceEnabled(marker)) {
            log(marker, null, TRACE_INT, format, argArray, null);
        }
    }

    @Override
    public void trace(Marker marker, String msg, Throwable t) {
        if (isTraceEnabled(marker)) {
            log(marker, null, TRACE_INT, msg, null, t);
        }
    }

    @Override
    public boolean isDebugEnabled() {
        return configuration.debug;
    }

    @Override
    public void debug(String msg) {
        if (isDebugEnabled()) {
            log(null, null, DEBUG_INT, msg, null, null);
        }
    }

    @Override
    public void debug(String format, Object arg) {
        if (isDebugEnabled()) {
            log(null, null, DEBUG_INT, format, new Object[]{arg}, null);
        }
    }

    @Override
    public void debug(String format, Object arg1, Object arg2) {
        if (isDebugEnabled()) {
            log(null, null, DEBUG_INT, format, new Object[]{arg1, arg2}, null);
        }
    }

    @Override
    public void debug(String format, Object... argArray) {
        if (isDebugEnabled()) {
            log(null, null, DEBUG_INT, format, argArray, null);
        }
    }

    @Override
    public void debug(String msg, Throwable t) {
        if (isDebugEnabled()) {
            log(null, null, DEBUG_INT, msg, null, t);
        }
    }

    @Override
    public boolean isDebugEnabled(Marker marker) {
        return configuration.debug;
    }

    @Override
    public void debug(Marker marker, String msg) {
        if (isDebugEnabled(marker)) {
            log(marker, null, DEBUG_INT, msg, null, null);
        }
    }

    @Override
    public void debug(Marker marker, String format, Object arg) {
        if (isDebugEnabled(marker)) {
            log(marker, null, DEBUG_INT, format, new Object[]{arg}, null);
        }
    }

    @Override
    public void debug(Marker marker, String format, Object arg1, Object arg2) {
        if (isDebugEnabled(marker)) {
            log(marker, null, DEBUG_INT, format, new Object[]{arg1, arg2}, null);
        }
    }

    @Override
    public void debug(Marker marker, String format, Object... arguments) {
        if (isDebugEnabled(marker)) {
            log(marker, null, DEBUG_INT, format, arguments, null);
        }
    }

    @Override
    public void debug(Marker marker, String msg, Throwable t) {
        if (isDebugEnabled(marker)) {
            log(marker, null, DEBUG_INT, msg, null, t);
        }
    }

    @Override
    public boolean isInfoEnabled() {
        return configuration.info;
    }

    @Override
    public void info(String msg) {
        if (isInfoEnabled()) {
            log(null, null, INFO_INT, msg, null, null);
        }
    }

    @Override
    public void info(String format, Object arg) {
        if (isInfoEnabled()) {
            log(null, null, INFO_INT, format, new Object[]{arg}, null);
        }
    }

    @Override
    public void info(String format, Object arg1, Object arg2) {
        if (isInfoEnabled()) {
            log(null, null, INFO_INT, format, new Object[]{arg1, arg2}, null);
        }
    }

    @Override
    public void info(String format, Object... argArray) {
        if (isInfoEnabled()) {
            log(null, null, INFO_INT, format, argArray, null);
        }
    }

    @Override
    public void info(String msg, Throwable t) {
        if (isInfoEnabled()) {
            log(null, null, INFO_INT, msg, null, t);
        }
    }

    @Override
    public boolean isInfoEnabled(Marker marker) {
        return configuration.info;
    }

    @Override
    public void info(Marker marker, String msg) {
        if (isInfoEnabled(marker)) {
            log(marker, null, INFO_INT, msg, null, null);
        }
    }

    @Override
    public void info(Marker marker, String format, Object arg) {
        if (isInfoEnabled(marker)) {
            log(marker, null, INFO_INT, format, new Object[]{arg}, null);
        }
    }

    @Override
    public void info(Marker marker, String format, Object arg1, Object arg2) {
        if (isInfoEnabled(marker)) {
            log(marker, null, INFO_INT, format, new Object[]{arg1, arg2}, null);
        }
    }

    @Override
    public void info(Marker marker, String format, Object... arguments) {
        if (isInfoEnabled(marker)) {
            log(marker, null, INFO_INT, format, arguments, null);
        }
    }

    @Override
    public void info(Marker marker, String msg, Throwable t) {
        if (isInfoEnabled(marker)) {
            log(marker, null, INFO_INT, msg, null, t);
        }
    }

    @Override
    public boolean isWarnEnabled() {
        return configuration.warn;
    }

    @Override
    public void warn(String msg) {
        if (isWarnEnabled()) {
            log(null, null, WARN_INT, msg, null, null);
        }
    }

    @Override
    public void warn(String format, Object arg) {
        if (isWarnEnabled()) {
            log(null, null, WARN_INT, format, new Object[]{arg}, null);
        }
    }

    @Override
    public void warn(String format, Object arg1, Object arg2) {
        if (isWarnEnabled()) {
            log(null, null, WARN_INT, format, new Object[]{arg1, arg2}, null);
        }
    }

    @Override
    public void warn(String format, Object... argArray) {
        if (isWarnEnabled()) {
            log(null, null, WARN_INT, format, argArray, null);
        }
    }

    @Override
    public void warn(String msg, Throwable t) {
        if (isWarnEnabled()) {
            log(null, null, WARN_INT, msg, null, t);
        }
    }

    @Override
    public boolean isWarnEnabled(Marker marker) {
        return true;
    }

    @Override
    public void warn(Marker marker, String msg) {
        if (isWarnEnabled(marker)) {
            log(marker, null, WARN_INT, msg, null, null);
        }
    }

    @Override
    public void warn(Marker marker, String format, Object arg) {
        if (isWarnEnabled(marker)) {
            log(marker, null, WARN_INT, format, new Object[]{arg}, null);
        }
    }

    @Override
    public void warn(Marker marker, String format, Object arg1, Object arg2) {
        if (isWarnEnabled(marker)) {
            log(marker, null, WARN_INT, format, new Object[]{arg1, arg2}, null);
        }
    }

    @Override
    public void warn(Marker marker, String format, Object... arguments) {
        if (isWarnEnabled(marker)) {
            log(marker, null, WARN_INT, format, arguments, null);
        }
    }

    @Override
    public void warn(Marker marker, String msg, Throwable t) {
        if (isWarnEnabled(marker)) {
            log(marker, null, WARN_INT, msg, null, t);
        }
    }

    @Override
    public boolean isErrorEnabled() {
        return configuration.error;
    }

    @Override
    public void error(String msg) {
        if (isErrorEnabled()) {
            log(null, null, ERROR_INT, msg, null, null);
        }
    }

    @Override
    public void error(String format, Object arg) {
        if (isErrorEnabled()) {
            log(null, null, ERROR_INT, format, new Object[]{arg}, null);
        }
    }

    @Override
    public void error(String format, Object arg1, Object arg2) {
        if (isErrorEnabled()) {
            log(null, null, ERROR_INT, format, new Object[]{arg1, arg2}, null);
        }
    }

    @Override
    public void error(String format, Object... arguments) {
        if (isErrorEnabled()) {
            log(null, null, ERROR_INT, format, arguments, null);
        }
    }

    @Override
    public void error(String msg, Throwable t) {
        if (isErrorEnabled()) {
            log(null, null, ERROR_INT, msg, null, t);
        }
    }

    @Override
    public boolean isErrorEnabled(Marker marker) {
        return configuration.error;
    }

    @Override
    public void error(Marker marker, String msg) {
        if (isErrorEnabled(marker)) {
            log(marker, null, ERROR_INT, msg, null, null);
        }
    }

    @Override
    public void error(Marker marker, String format, Object arg) {
        if (isErrorEnabled(marker)) {
            log(marker, null, ERROR_INT, format, new Object[]{arg}, null);
        }
    }

    @Override
    public void error(Marker marker, String format, Object arg1, Object arg2) {
        if (isErrorEnabled(marker)) {
            log(marker, null, ERROR_INT, format, new Object[]{arg1, arg2}, null);
        }
    }

    @Override
    public void error(Marker marker, String format, Object... arguments) {
        if (isErrorEnabled(marker)) {
            log(marker, null, ERROR_INT, format, arguments, null);
        }
    }

    @Override
    public void error(Marker marker, String msg, Throwable t) {
        if (isErrorEnabled(marker)) {
            log(marker, null, ERROR_INT, msg, null, t);
        }
    }

    @Override
    public void log(Marker marker, String fqcn, int level, String message, Object[] argArray, Throwable t) {
        FormattingTuple ft = MessageFormatter.arrayFormat(message, argArray);
        if (t == null) {
            t = ft.getThrowable();
        }
        message = ft.getMessage();
        if (configuration.location) {
            // append location
            StackTraceElement caller = getCaller();
            if (caller == null) {
                message += " (???)";
            } else if (caller.isNativeMethod()) {
                message += " {" + caller.getFileName() + ":" + caller.getLineNumber() + " - native " + caller.getMethodName() + "}";
            } else {
                message += " {" + caller.getFileName() + ":" + caller.getLineNumber() + " - " + getSimpleClassName(caller.getClassName()) + "." + caller.getMethodName() + "}";
            }
        }
        if (configuration.levels != null) {
            // map logging level to effective level
            Integer value = configuration.levels.get(level);
            if (value != null) {
                level = value;
            }
        }
        switch (level) {
            case TRACE_INT:
                Log.v(name, message, t);
                break;
            case DEBUG_INT:
                Log.d(name, message, t);
                break;
            case INFO_INT:
                Log.i(name, message, t);
                break;
            case WARN_INT:
                Log.w(name, message, t);
                break;
            case ERROR_INT:
                Log.e(name, message, t);
                break;
        }
    }

    /**
     * Get callers stacktrace element.
     * <p>
     * Check stack for callers to package "org.slf4j."
     *
     * @return callers stack element, or {@code null}, if not available.
     */
    private StackTraceElement getCaller() {
        boolean lookingForLogger = true;
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        for (StackTraceElement element : stackTrace) {
            String cname = element.getClassName();
            boolean isLoggerImpl = cname.startsWith("org.slf4j.");
//            System.out.println(cname+ ", looking: " +lookingForLogger+ ", found: " + isLoggerImpl);
            if (lookingForLogger) {
                // Skip all frames until we have found the first logger frame.
                if (isLoggerImpl) {
                    lookingForLogger = false;
                }
            } else {
                if (!isLoggerImpl) {
                    // skip reflection call
                    if (!cname.startsWith("java.lang.reflect.") && !cname.startsWith("sun.reflect.")) {
                        // We've found the relevant frame.
                        return element;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Extract simple (unqualified) class name.
     *
     * @param className qualified class name
     * @return simple class name
     */
    private String getSimpleClassName(String className) {
        int index = className.lastIndexOf('$');
        if (index >= 0 && (index + 1) < className.length()) {
            return className.substring(index + 1);
        }
        index = className.lastIndexOf('.');
        if (index >= 0 && (index + 1) < className.length()) {
            return className.substring(index + 1);
        }
        return className;
    }

    private static class InternalConfiguration {
        public final boolean trace;
        public final boolean debug;
        public final boolean info;
        public final boolean warn;
        public final boolean error;
        public final boolean location;
        public final Map<Integer, Integer> levels;

        public InternalConfiguration(Configuration configuration) {
            this.trace = configuration.trace;
            this.debug = configuration.debug;
            this.info = configuration.info;
            this.warn = configuration.warn;
            this.error = configuration.error;
            this.location = configuration.location;
            if (configuration.levels != null) {
                this.levels = new HashMap<Integer, Integer>();
                this.levels.putAll(configuration.levels);
            } else {
                this.levels = null;
            }
        }
    }

    public static class Configuration {
        public boolean trace;
        public boolean debug;
        public boolean info;
        public boolean warn;
        public boolean error;
        public boolean location;
        public Map<Integer, Integer> levels;

        public Configuration() {
            trace = true;
            debug = true;
            info = true;
            warn = true;
            error = true;
            location = true;
            this.levels = new HashMap<Integer, Integer>();
            this.levels.put(TRACE_INT, INFO_INT);
            this.levels.put(DEBUG_INT, INFO_INT);
            this.levels.put(INFO_INT, INFO_INT);
            this.levels.put(WARN_INT, WARN_INT);
            this.levels.put(ERROR_INT, ERROR_INT);
        }

        public Configuration(String configuration) {
            trace = configuration.contains("t");
            debug = configuration.contains("d");
            info = configuration.contains("i");
            warn = configuration.contains("w");
            error = configuration.contains("e");
            location = configuration.contains("l");
            this.levels = new HashMap<Integer, Integer>();
            this.levels.put(TRACE_INT, INFO_INT);
            this.levels.put(DEBUG_INT, INFO_INT);
            this.levels.put(INFO_INT, INFO_INT);
            this.levels.put(WARN_INT, WARN_INT);
            this.levels.put(ERROR_INT, ERROR_INT);
        }
    }
}
