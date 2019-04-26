package org.eclipse.californium.elements.exception;

/**
 * Exception indicating a connector-specific issue occurred
 */
public class ConnectorException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Create new instance.
     */
    public ConnectorException() {
        super();
    }

    /**
     * Create new instance with message.
     *
     * @param message message
     */
    public ConnectorException(String message) {
        super(message);
    }
}
