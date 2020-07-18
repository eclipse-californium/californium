/*******************************************************************************

 * Copyright (c) 2016, Jim Schaad
 * Copyright (c) 2018, Tobias Andersson, RISE SICS
 * Copyright (c) 2018, Rikard Höglund, RISE SICS
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
     
 ******************************************************************************/
package org.eclipse.californium.cose;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.scandium.dtls.cipher.CCMBlockCipher;

/**
 * 
 * This class is copied from the COSE Java repository. Changes made: Directly
 * changed the used cipher to Scandiums CCMBlockCipher code. Removing support
 * for a wider array of AES algorithms.
 *
 */
public abstract class EncryptCommon extends Message {

	private final static int AES_CCM_16_IV_LENGTH = 13;
	private final static int AES_CCM_64_IV_LENGTH = 7;
	protected String context;
	protected byte[] rgbEncrypt;

	protected byte[] decryptWithKey(byte[] rgbKey) throws CoseException {
		CBORObject algX = findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(algX);

		if (rgbEncrypt == null)
			throw new CoseException("No Encrypted Content Specified");

		if (!isSupportedAesCcm(alg)) {
			throw new CoseException("Unsupported Algorithm Specified");
		}

		AES_CCM_Decrypt(alg, rgbKey);

		return rgbContent;
	}

	void encryptWithKey(byte[] rgbKey) throws CoseException, IllegalStateException {
		CBORObject algX = findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(algX);

		if (rgbContent == null)
			throw new CoseException("No Content Specified");

		if (!isSupportedAesCcm(alg)) {
			throw new CoseException("Unsupported Algorithm Specified");
		}

		AES_CCM_Encrypt(alg, rgbKey);
	}

	//Method taken from EncryptCommon in COSE. This will provide the full AAD / Encrypt0-structure.
    private byte[] getAADBytes() {
        CBORObject obj = CBORObject.NewArray();
        
        obj.Add(context);
        
        if (objProtected.size() == 0) {
        	obj.Add(CBORObject.FromObject(Bytes.EMPTY));
        } else {
        	obj.Add(objProtected.EncodeToBytes());
        }
        
        obj.Add(CBORObject.FromObject(externalData));
        
        return obj.EncodeToBytes();
    }

	private void AES_CCM_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException {
		// validate key
		if (rgbKey.length != alg.getKeySize() / Byte.SIZE) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate IV
		final int ivLen = ivLength(alg);
		CBORObject iv = findAttribute(HeaderKeys.IV);
		if (iv == null) {
			throw new CoseException("Missing IV during decryption");
		}
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV size is incorrect");
		}

		//Modified to use the full AAD here rather than just the external AAD
		// Tag length (last parameter) was also included
		byte[] aad = getAADBytes();
		
		try {
			rgbContent = CCMBlockCipher.decrypt(new SecretKeySpec(rgbKey, "AES"), iv.GetByteString(), aad,
					getEncryptedContent(), alg.getTagSize() / Byte.SIZE);
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (InvalidKeyException ex) {
			if (ex.getMessage().equals("Illegal key size")) {
				throw new CoseException("Unsupported key size", ex);
			}
			throw new CoseException("Decryption failure", ex);
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new CoseException("Decryption failure", ex);
		}
	}

	private void AES_CCM_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException {
		SecureRandom random = new SecureRandom();

		// validate key
		if (rgbKey.length != alg.getKeySize() / Byte.SIZE) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate iv
		CBORObject iv = findAttribute(HeaderKeys.IV);
		int ivLen = ivLength(alg);
		if (iv == null) {
			byte[] tmp = new byte[ivLen];
			random.nextBytes(tmp);
			iv = CBORObject.FromObject(tmp);
			addAttribute(HeaderKeys.IV, iv, Attribute.UNPROTECTED);
		} else {
			if (iv.getType() != CBORType.ByteString) {
				throw new CoseException("IV is incorreclty formed.");
			}
			if (iv.GetByteString().length > ivLen) {
				throw new CoseException("IV is too long.");
			}
		}
		
		//Modified to use the full AAD here rather than just the external AAD
		// Tag length (last parameter) was also included
		byte[] aad = getAADBytes();
		
		try {
			rgbEncrypt = CCMBlockCipher.encrypt(new SecretKeySpec(rgbKey, "AES"), iv.GetByteString(), aad, GetContent(),
					alg.getTagSize() / Byte.SIZE);
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Encryption failure", ex);
		}
	}

	/**
	 * Used to obtain the encrypted content for the cases where detached content
	 * is requested.
	 * 
	 * @return bytes of the encrypted content
	 * @throws CoseException if content has not been encrypted
	 */
	public byte[] getEncryptedContent() throws CoseException {
		if (rgbEncrypt == null)
			throw new CoseException("No Encrypted Content Specified");

		return rgbEncrypt;
	}

	/**
	 * Set the encrypted content for detached content cases.
	 * 
	 * @param rgb encrypted content to be used
	 */
	public void setEncryptedContent(byte[] rgb) {
		rgbEncrypt = rgb;
	}

	/**
	 * Get IV length in bytes.
	 * 
	 * @param alg algorithm ID:
	 * @return iv length
	 */
	public static int ivLength(AlgorithmID alg) {
		switch (alg) {
		case AES_CCM_16_64_128:
		case AES_CCM_16_128_128:
			return AES_CCM_16_IV_LENGTH;
		case AES_CCM_64_64_128:
		case AES_CCM_64_128_128:
			return AES_CCM_64_IV_LENGTH;
		default:
			return -1;
		}
	}

	/**
	 * Check if an algorithm is supported.
	 * 
	 * @param alg the algorithm
	 * @return if it is supported
	 */
	public static boolean isSupportedAesCcm(AlgorithmID alg) {
		if (ivLength(alg) == -1) {
			return false;
		} else {
			return true;
		}
	}
}
