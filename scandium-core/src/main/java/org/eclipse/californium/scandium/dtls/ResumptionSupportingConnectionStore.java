package org.eclipse.californium.scandium.dtls;

/**
 * A connection store which adds support of connection resumption.
 * 
 * @since 1.1
 */
public interface ResumptionSupportingConnectionStore extends ConnectionStore {

	/**
	 * Mark all connections as resumption required.
	 * 
	 */
	void markAllAsResumptionRequired();
	
}
