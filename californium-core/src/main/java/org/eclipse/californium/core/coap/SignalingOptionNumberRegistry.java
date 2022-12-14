package org.eclipse.californium.core.coap;

import org.eclipse.californium.core.coap.CoAP.SignalingCode;
import org.eclipse.californium.core.coap.OptionNumberRegistry.OptionFormat;

public class SignalingOptionNumberRegistry {
	
	// RFC 8323 : https://datatracker.ietf.org/doc/html/rfc8323#section-11.2
	public static final int MAX_MESSAGE_SIZE= 2;
	public static final int BLOCK_WISE_TRANSFER= 4;
	public static final int CUSTODY= 2;
	public static final int ALTERNATIVE_ADDRESS= 2;
	public static final int HOLD_OFF= 4;
	public static final int BAD_CSM_OPTION= 2;
	
	/**
	 * Signaling Option names.
	 */
	public static class Names {
		// RFC 8323 : https://datatracker.ietf.org/doc/html/rfc8323#section-11.2
		public static final String Max_Message_Size	= "Max-Message-Size";
		public static final String Block_Wise_Transfer	= "Block-Wise-Transfer";
		public static final String Custody	= "Custody";
		public static final String Alternative_Address	= "Alternative-Address";
		public static final String Hold_Off	= "Hold-Off";
		public static final String Bad_CSM_Option	= "Bad-CSM-Option";
	}

	public static String toString(SignalingCode code, int optionNumber) {
		switch (code) {
		case CSM:
			switch (optionNumber) {
			case MAX_MESSAGE_SIZE:
				return Names.Max_Message_Size;
			case BLOCK_WISE_TRANSFER:
				return Names.Block_Wise_Transfer;
			}
		case PING:
		case PONG:
			switch (optionNumber) {
			case CUSTODY:
				return Names.Custody;
			}
		case RELEASE:
			switch (optionNumber) {
			case ALTERNATIVE_ADDRESS:
				return Names.Alternative_Address;
			case HOLD_OFF:
				return Names.Hold_Off;
			}
		case ABORT:
			switch (optionNumber) {
			case BAD_CSM_OPTION:
				return Names.Bad_CSM_Option;
			}
		}		
		return String.format("Unknown (%s, %d)", optionNumber);
	}

	public static void assertValueLength(SignalingCode code, int optionNumber, int valueLength) {
		int min = 0;
		int max = 65535 + 269;
		switch (code) {
		case CSM:
			switch (optionNumber) {
			case MAX_MESSAGE_SIZE:
				max=4;
				break;
			case BLOCK_WISE_TRANSFER:
				max=0;
				break;
			}
		case PING:
		case PONG:
			switch (optionNumber) {
			case CUSTODY:
				max=0;
				break;
			}
		case RELEASE:
			switch (optionNumber) {
			case ALTERNATIVE_ADDRESS:
				min=1;
				max=255;
				break;
			case HOLD_OFF:
				max=3;
				break;
			}
		case ABORT:
			switch (optionNumber) {
			case BAD_CSM_OPTION:
				max=2;
				break;
			}
		}
		
		if (valueLength < min || valueLength > max) {
			String name = toString(code, optionNumber);
			if (min == max) {
				if (min == 0) {
					throw new IllegalArgumentException(
							"Option " + name + " value of " + valueLength + " bytes must be empty.");
				} else {
					throw new IllegalArgumentException(
							"Option " + name + " value of " + valueLength + " bytes must be " + min + " bytes.");
				}
			} else {
				throw new IllegalArgumentException("Option " + name + " value of " + valueLength
						+ " bytes must be in range of [" + min + "-" + max + "] bytes.");
			}
		}
	}
	
	/**
	 * Checks whether an option has a single value.
	 * 
	 * @param optionNumber
	 *            the option number
	 * @return {@code true} if the option has a single value
	 */
	public static boolean isSingleValue(SignalingCode code, int optionNumber) {
		switch (code) {
		case CSM:
			switch (optionNumber) {
			case MAX_MESSAGE_SIZE:
				return true;
			case BLOCK_WISE_TRANSFER:
				return true;
			}
		case PING:
		case PONG:
			switch (optionNumber) {
			case CUSTODY:
				return true;
			}
		case RELEASE:
			switch (optionNumber) {
			case ALTERNATIVE_ADDRESS:
				return true;
			case HOLD_OFF:
				return true;
			}
		case ABORT:
			switch (optionNumber) {
			case BAD_CSM_OPTION:
				return true;
			}
		}
		return true;
	}

	public static OptionFormat getFormatByNr(SignalingCode code, int optionNumber) {
		switch (code) {
		case CSM:
			switch (optionNumber) {
			case MAX_MESSAGE_SIZE:
				return OptionFormat.INTEGER;
			case BLOCK_WISE_TRANSFER:
				return OptionFormat.EMPTY;
			}
		case PING:
		case PONG:
			switch (optionNumber) {
			case CUSTODY:
				return OptionFormat.EMPTY;
			}
		case RELEASE:
			switch (optionNumber) {
			case ALTERNATIVE_ADDRESS:
				return OptionFormat.STRING;
			case HOLD_OFF:
				return OptionFormat.INTEGER;
			}
		case ABORT:
			switch (optionNumber) {
			case BAD_CSM_OPTION:
				return OptionFormat.INTEGER;
			}
		}
		return OptionFormat.UNKNOWN;
	}
}
