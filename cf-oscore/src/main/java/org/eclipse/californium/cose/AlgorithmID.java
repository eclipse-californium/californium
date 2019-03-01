/*******************************************************************************

 * Original from https://github.com/cose-wg/COSE-JAVA Commit 1a20373
 *
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
     
 ******************************************************************************/
package org.eclipse.californium.cose;

import com.upokecenter.cbor.CBORObject;

/**
 *
 * @author jimsch
 */
public enum AlgorithmID {
    AES_GCM_128(1, 128, 128),
    AES_GCM_192(2, 192, 128),
    AES_GCM_256(3, 256, 128),
    HMAC_SHA_256_64(4, 256, 64),
    HMAC_SHA_256(5, 256, 256),
    HMAC_SHA_384(6, 384, 384),
    HMAC_SHA_512(7, 512, 512),
    AES_CCM_16_64_128(10, 128, 64),
    AES_CCM_16_64_256(11, 256, 64),
    AES_CCM_64_64_128(12, 128, 64),
    AES_CCM_64_64_256(13, 256, 64),
    AES_CBC_MAC_128_64(14, 128, 64),
    AES_CBC_MAC_256_64(15, 256, 64),
    AES_CBC_MAC_128_128(25, 128, 128),
    AES_CBC_MAC_256_128(26, 256, 128),
    AES_CCM_16_128_128(30, 128, 128),
    AES_CCM_16_128_256(31, 256, 128),
    AES_CCM_64_128_128(32, 128, 128),
    AES_CCM_64_128_256(33, 256, 128),
    
    AES_KW_128(-3, 128, 64),
    AES_KW_192(-4, 192, 64),
    AES_KW_256(-5, 256, 64),
    Direct(-6, 0, 0),
    ECDSA_256(-7, 0, 0),
    HKDF_HMAC_SHA_256(-10, 256, 0),
    HKDF_HMAC_SHA_512(-11, 512, 0),
    HKDF_HMAC_AES_128(-12, 128, 0),
    HKDF_HMAC_AES_256(-13, 256, 0),
    ECDSA_384(-35, 0, 0),
    ECDSA_512(-36, 0, 0),
    EDDSA(-8, 0, 0),
    
    ECDH_ES_HKDF_256(-25, 0, 0),
    ECDH_ES_HKDF_512(-26, 0, 0),
    ECDH_SS_HKDF_256(-27, 0, 0),
    ECDH_SS_HKDF_512(-28, 0, 0),
    ECDH_ES_HKDF_256_AES_KW_128(-29, 0, 0),
    ECDH_ES_HKDF_256_AES_KW_192(-30, 0, 0),
    ECDH_ES_HKDF_256_AES_KW_256(-31, 0, 0),
    ECDH_SS_HKDF_256_AES_KW_128(-32, 0, 0),
    ECDH_SS_HKDF_256_AES_KW_192(-33, 0, 0),
    ECDH_SS_HKDF_256_AES_KW_256(-34, 0, 0),
    ;
 
    private final CBORObject value;
    private final int cbitKey;
    private final int cbitTag;
    
    AlgorithmID(int value, int cbitKey, int cbitTag) {
        this.value = CBORObject.FromObject(value);
        this.cbitKey = cbitKey;
        this.cbitTag = cbitTag;
    }    
    
    public static AlgorithmID FromCBOR(CBORObject obj) throws CoseException {
        if (obj == null) throw new CoseException("No Algorithm Specified");
        for (AlgorithmID alg : AlgorithmID.values()) {
            if (obj.equals(alg.value)) return alg;
        }
        throw new CoseException("Unknown Algorithm Specified");
    }
    
    public CBORObject AsCBOR() {
        return value;
    }
    
    public int getKeySize() {
        return cbitKey;
    }
    
    public int getTagSize() {
        return cbitTag;
    }
}
