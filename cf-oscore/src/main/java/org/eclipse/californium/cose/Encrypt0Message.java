/*******************************************************************************

 * Copyright (c) 2016, Jim Schaad
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.

 * Neither the name of COSE-JAVA nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Contributors:
 *    Achim Kraus (Bosch Software Innovations GmbH) - update to javadoc
 *                                                    align with cose 1.0
 *                                                    commit 629912b94ea80c4c6
 ******************************************************************************/
package org.eclipse.californium.cose;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/**
 * 
 * This class is copied from the COSE Java repository to force use of the
 * changed EncryptCommon. No change made in this class.
 *
 */
public class Encrypt0Message extends EncryptCommon {

	/**
	 * Create a Encrypt0Message object. This object corresponds to the encrypt
	 * message format in COSE. The leading CBOR tag will be emitted. The message
	 * content will be emitted.
	 */
	public Encrypt0Message() {
		this(true, true);
	}

	/**
	 * Create a Encrypt0Message object. This object corresponds to the encrypt
	 * message format in COSE.
	 * 
	 * @param emitTag is the leading CBOR tag emitted
	 * @param emitContent is the content emitted
	 */
	public Encrypt0Message(boolean emitTag, boolean emitContent) {
		context = "Encrypt0";
		messageTag = MessageTag.Encrypt0;
		this.emitTag = emitTag;
		this.emitContent = emitContent;
	}

	@Override
	public void DecodeFromCBORObject(CBORObject obj) throws CoseException {
		if (obj.size() != 3)
			throw new CoseException("Invalid Encrypt0 structure");

		if (obj.get(0).getType() == CBORType.ByteString) {
			if (obj.get(0).GetByteString().length == 0) {
				rgbProtected = new byte[0];
				objProtected = CBORObject.NewMap();
			} else {
				rgbProtected = obj.get(0).GetByteString();
				objProtected = CBORObject.DecodeFromBytes(rgbProtected);
				if (objProtected.getType() != CBORType.Map)
					throw new CoseException("Invalid Encrypt0 structure");
			}

		} else
			throw new CoseException("Invalid Encrypt0 structure");

		if (obj.get(1).getType() == CBORType.Map)
			objUnprotected = obj.get(1);
		else
			throw new CoseException("Invalid Encrypt0 structure");

		if (obj.get(2).getType() == CBORType.ByteString)
			rgbEncrypt = obj.get(2).GetByteString();
		else if (!obj.get(2).isNull())
			throw new CoseException("Invalid Encrypt0 structure");
	}

	/**
	 * Internal function used to construct the CBORObject
	 * 
	 * @return the constructed CBORObject
	 * @throws CoseException if the content has not yet been encrypted
	 */
	@Override
	protected CBORObject EncodeCBORObject() throws CoseException {
		if (rgbEncrypt == null)
			throw new CoseException("Encrypt function not called");

		CBORObject obj = CBORObject.NewArray();
		if (objProtected.size() > 0)
			obj.Add(objProtected.EncodeToBytes());
		else
			obj.Add(CBORObject.FromObject(new byte[0]));

		obj.Add(objUnprotected);

		if (emitContent)
			obj.Add(rgbEncrypt);
		else
			obj.Add(CBORObject.Null);

		return obj;
	}

	/**
	 * Decrypt the message using the passed in key.
	 * 
	 * @param rgbKey key for decryption
	 * @return the decrypted content
     * @throws CoseException - Error during decryption
	 */
	public byte[] decrypt(byte[] rgbKey) throws CoseException {
		return super.decryptWithKey(rgbKey);
	}

	/**
	 * Encrypt the message using the passed in key.
	 * 
	 * @param rgbKey key used for encryption
     * @throws CoseException - Error during decryption
     * @throws IllegalStateException - Error during decryption
	 */
	public void encrypt(byte[] rgbKey) throws CoseException, IllegalStateException {
		super.encryptWithKey(rgbKey);
	}
}
