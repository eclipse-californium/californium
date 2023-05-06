/*******************************************************************************
 * Copyright (c) 2023 Rogier Cobben.
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
 *    Rogier Cobben - Added map based signaling option registry
 ******************************************************************************/
package org.eclipse.californium.core.coap.option;

import org.eclipse.californium.core.coap.CoAP.SignalingCode;

/**
 * Signaling Options registry.
 * 
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8323#section-11.2"
 *      target= "_blank">RFC8323 11.2. CoAP Signaling Option Numbers
 *      Registry</a>
 *
 */
public class SignalingOptionRegistry extends MapBasedOptionRegistry {

	/**
	 * Signaling Option numbers.
	 */
	public static class Numbers {

		public static final int MAX_MESSAGE_SIZE = 2;
		public static final int BLOCK_WISE_TRANSFER = 4;
		public static final int CUSTODY = 2;
		public static final int ALTERNATIVE_ADDRESS = 2;
		public static final int HOLD_OFF = 4;
		public static final int BAD_CSM_OPTION = 2;
	}

	/**
	 * Signaling Option names.
	 */
	public static class Names {

		public static final String Max_Message_Size = "Max-Message-Size";
		public static final String Block_Wise_Transfer = "Block-Wise-Transfer";
		public static final String Custody = "Custody";
		public static final String Alternative_Address = "Alternative-Address";
		public static final String Hold_Off = "Hold-Off";
		public static final String Bad_CSM_Option = "Bad-CSM-Option";
	}

	/**
	 * Max-Message-Size Capability Option. Applicable in CSM Messages.
	 * 
	 * @see <a href=
	 *      "https://datatracker.ietf.org/doc/html/rfc8323#section-5.3.1"
	 *      target= "_blank">RFC8323 5.3.1. Max-Message-Size Capability
	 *      Option</a>
	 */
	public static final IntegerOptionDefinition MAX_MESSAGE_SIZE = new IntegerOptionDefinition(Numbers.MAX_MESSAGE_SIZE,
			Names.Max_Message_Size, true, 0, 4);

	/**
	 * Block-Wise-Transfer Capability Option. Applicable in CSM Messages.
	 * 
	 * @see <a href=
	 *      "https://datatracker.ietf.org/doc/html/rfc8323#section-5.3.2"
	 *      target= "_blank">RFC8323 5.3.2. Block-Wise-Transfer Capability
	 *      Option</a>
	 */
	public static final EmptyOptionDefinition BLOCK_WISE_TRANSFER = new EmptyOptionDefinition(
			Numbers.BLOCK_WISE_TRANSFER, Names.Block_Wise_Transfer);

	/**
	 * Custody Option. Applicable in Ping Messages.
	 * 
	 * @see <a href=
	 *      "https://datatracker.ietf.org/doc/html/rfc8323#section-5.4.1"
	 *      target= "_blank">RFC8323 5.4.1. Custody Option</a>
	 */
	public static final EmptyOptionDefinition CUSTODY = new EmptyOptionDefinition(Numbers.CUSTODY, Names.Custody);

	/**
	 * Alternative-Address Option. Applicable in Release Messages.
	 * 
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8323#section-5.5"
	 *      target= "_blank">RFC8323 5.5. Release Messages</a>
	 */
	public static final StringOptionDefinition ALTERNATIVE_ADDRESS = new StringOptionDefinition(
			Numbers.ALTERNATIVE_ADDRESS, Names.Alternative_Address, false, 1, 255);

	/**
	 * Hold-Off Option. Applicable in Release Messages.
	 * 
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8323#section-5.5"
	 *      target= "_blank">RFC8323 5.5. Release Messages</a>
	 */
	public static final IntegerOptionDefinition HOLD_OFF = new IntegerOptionDefinition(Numbers.HOLD_OFF, Names.Hold_Off,
			true, 0, 3);

	/**
	 * Bad-CSM-Option Option. Applicable in Abort Messages.
	 * 
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8323#section-5.6"
	 *      target= "_blank">RFC8323 5.6. Abort Messages</a>
	 */
	public static final IntegerOptionDefinition BAD_CSM_OPTION = new IntegerOptionDefinition(Numbers.BAD_CSM_OPTION,
			Names.Bad_CSM_Option, true, 0, 2);

	/**
	 * Get definition by number always returns null, because MessageCode is
	 * necessary to discriminate signaling options.
	 */
	@Override
	public OptionDefinition getDefinitionByNumber(int optionNumber) {
		return null;
	}

	/**
	 * Registry with all signaling options.
	 */
	public static final SignalingOptionRegistry SIGNALING_OPTIONS = new SignalingOptionRegistry();

	private SignalingOptionRegistry() {
		super();
		put(SignalingCode.CSM.value, MAX_MESSAGE_SIZE);
		put(SignalingCode.CSM.value, BLOCK_WISE_TRANSFER);
		put(SignalingCode.PING.value, CUSTODY);
		put(SignalingCode.RELEASE.value, ALTERNATIVE_ADDRESS);
		put(SignalingCode.RELEASE.value, HOLD_OFF);
		put(SignalingCode.ABORT.value, BAD_CSM_OPTION);
	}
}
