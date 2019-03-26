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

import com.upokecenter.cbor.*;

/**
 * Internal class which supports the protected and unprotected attribute maps that
 * are common to the core COSE objects. 
 * <p>
 * In addition an attribute map is provided 
 * for attributes which will not be sent as part of the message, but which are needed
 * for the code to function correctly.  As an example of how this works, there are
 * some situations where the algorithm identifier is not sent as part of an encrypted message,
 * however it is needed in order to encrypt or decrypt the content so the application would set it
 * in the unsent package at send time - for encryption - or at receive time - for decryption.
 * 
 * @author jimsch
 */

public class Attribute {
    /**
     * Internal map of protected attributes
     */
    protected CBORObject objProtected = CBORObject.NewMap();
    
    /**
     * Internal map of unprotected attributes
    */
    protected CBORObject objUnprotected = CBORObject.NewMap();
    
    /**
     * Internal map of attributes which are not a part of the encoded message.
     */
    protected CBORObject objDontSend = CBORObject.NewMap();
    
    /**
     * The encoded byte string for the protected attributes.  If this variable is 
     * set then the message was either decoded or as been cryptographically signed/encrypted/maced.
     * If it is set, then do not allow objProtected to be modified.
     */
    protected byte[] rgbProtected;
    
    /**
     * Holder for the external data object that is authenticated as part of the 
     * message
     */
    protected byte[] externalData = new byte[0];
    
    /**
     * Used to place an attribute in the protected attribute map
     * Attributes placed in this map are part of the integrity check if the cryptographic algorithm supports authenticated data.
     * @deprecated As of COSE 0.9.1, use Attribute.PROTECT
     */
    @Deprecated
    public static final int ProtectedAttributes = 1;

    /**
     * Used to place an attribute in the unprotected attribute map
     * Attributes placed in this map are not integrity protected.
     * 
     * @deprecated As of COSE 0.9.1, use Attribute.UNPROTECT
     */
    @Deprecated
    public static final int UnprotectedAttributes = 2;

    /**
     * Used to place an attribute in the do not send attribute map
     * Attributes in this map are available for lookup and use but will not
     * be transmitted as part of the message.
     * 
     * @deprecated As of COSE 0.9.1, use Attribute.DO_NOT_SEND
     */
    @Deprecated 
    public static final int DontSendAttributes = 4;

    /**
     * Used to place an attribute in the protected attribute map
     * Attributes placed in this map are part of the integrity check if the cryptographic algorithm supports authenticated data.
     */
    public static final int PROTECTED = 1;

    /**
     * Used to place an attribute in the unprotected attribute map
     * Attributes placed in this map are not integrity protected.
     */
    public static final int UNPROTECTED = 2;

    /**
     * Used to place an attribute in the do not send attribute map
     * Attributes in this map are available for lookup and use but will not
     * be transmitted as part of the message.
     */
    public static final int DO_NOT_SEND = 4;
    
    /**
     * Set an attribute in the COSE object.  
     * Setting an attribute in one map will remove it from all other maps as a side effect.
     * 
     * @param label CBOR object which identifies the attribute in the map
     * @param value CBOR object which contains the value of the attribute
     * @param where Identifies which of the buckets to place the attribute in.
     *      ProtectedAttributes - attributes cryptographically protected
     *      UnprotectedAttributes - attributes not cryptographically protected
     *      DontSendAttributes - attributes used locally and not transmitted
     * @exception CoseException COSE Package exception
     */

    public void addAttribute(CBORObject label, CBORObject value, int where) throws CoseException {
        removeAttribute(label);
        if ((label.getType() != CBORType.Number) &&  (label.getType() != CBORType.TextString)) {
            throw new CoseException("Labels must be integers or strings");
        }
        switch (where) {
            case PROTECTED:
                if (rgbProtected != null) throw new CoseException("Cannot modify protected attribute if signature has been computed");
                objProtected.Add(label, value);
                break;
                
            case UNPROTECTED:
                objUnprotected.Add(label, value);
                break;
                
            case DO_NOT_SEND:
                objDontSend.Add(label, value);
                break;
                
            default:
                throw new CoseException("Invalid attribute location given");
        }
    }
    
    /**
     * Set an attribute in the COSE object.
     * Setting an attribute in one map will remove it from all other maps as a side effect.
     * 
     * @param label HeaderKeys label which identifies the attribute in the map
     * @param value CBOR object which contains the value of the attribute
     * @param where Identifies which of the buckets to place the attribute in.
     *      ProtectedAttributes - attributes cryptographically protected
     *      UnprotectedAttributes - attributes not cryptographically protected
     *      DontSendAttributes - attributes used locally and not transmitted
     * @exception CoseException COSE Package exception
     */
    public void addAttribute(HeaderKeys label, CBORObject value, int where) throws CoseException {
        addAttribute(label.AsCBOR(), value, where);
    }
    
    /**
     * Set an attribute in the COSE object.
     * Setting an attribute in one map will remove it from all other maps as a side effect.
     * 
     * @param label HeaderKeys label which identifies the attribute in the map
     * @param value CBOR object which contains the value of the attribute
     * @param where Identifies which of the buckets to place the attribute in.
     *      ProtectedAttributes - attributes cryptographically protected
     *      UnprotectedAttributes - attributes not cryptographically protected
     *      DontSendAttributes - attributes used locally and not transmitted
     * @exception CoseException COSE Package exception
     */
    public void addAttribute(HeaderKeys label, byte[] value, int where) throws CoseException {
        addAttribute(label.AsCBOR(), CBORObject.FromObject(value), where);
    }

    /**
     * Set an attribute in the protect bucket of the COSE object
     * 
     * @param label CBOR object which identifies the attribute in the map
     * @param value CBOR object which contains the value of the attribute
     * 
     * @deprecated As of COSE 0.9.0, use addAttribute(CBORObject, CBORObject, Attribute.PROTECTED);
     * @exception CoseException COSE Package exception
     */
    @Deprecated
    public void AddProtected(CBORObject label, CBORObject value) throws CoseException {
        addAttribute(label, value, PROTECTED);
    }
    
    /**
     * Set an attribute in the protect bucket of the COSE object
     * 
     * @param label HeaderKeys label which identifies the attribute in the map
     * @param value CBOR object which contains the value of the attribute
     * 
     * @deprecated As of COSE 0.9.0, use addAttribute(HeaderKeys, CBORObject, Attribute.PROTECTED);
     * @exception CoseException COSE Package exception
     */
    @Deprecated
    public void AddProtected(HeaderKeys label, CBORObject value) throws CoseException {
        addAttribute(label, value, PROTECTED);
    }
    
    /**
     * Set an attribute in the protect bucket of the COSE object
     * 
     * @param label CBOR object which identifies the attribute in the map
     * @param value byte array of value
     * 
     * @deprecated As of COSE 0.9.0, use addAttribute(HeaderKeys, byte[], Attribute.PROTECTED);
     * @exception CoseException COSE Package exception
     */
    @Deprecated
    public void AddProtected(HeaderKeys label, byte[] value) throws CoseException {
        addAttribute(label, value, PROTECTED);
    }

    /**
     * Set an attribute in the unprotected bucket of the COSE object
     * 
     * @param label value identifies the attribute in the map
     * @param value value to be associated with the label
     * 
     * @deprecated As of COSE 0.9.1, use addAttribute(HeaderKeys, byte[], Attribute.UNPROTECTED);
     * @exception CoseException COSE Package exception
     */
    @Deprecated
    public void AddUnprotected(CBORObject label, CBORObject value) throws CoseException {
        addAttribute(label, value, UNPROTECTED);
    }
    
    /**
     * Set an attribute in the unprotected bucket of the COSE object
     * 
     * @param label identifies the attribute in the map
     * @param value value to be associated with the label
     * 
     * @deprecated As of COSE 0.9.1, use addAttribute(HeaderKeys, byte[], Attribute.UNPROTECTED);
     * @exception CoseException COSE Package exception
     */
    @Deprecated
    public void AddUnprotected(HeaderKeys label, CBORObject value) throws CoseException {
        addAttribute(label, value, UNPROTECTED);
    }
    
    /**
     * Set an attribute in the unprotected bucket of the COSE object
     * 
     * @param label identifies the attribute in the map
     * @param value value to be associated with the label
     * 
     * @deprecated As of COSE 0.9.1, use addAttribute(HeaderKeys, byte[], Attribute.UNPROTECTED);
     * @exception CoseException COSE Package exception
     */
    @Deprecated
    public void AddUnprotected(HeaderKeys label, byte[] value) throws CoseException {
        addAttribute(label, value, UNPROTECTED);
    }

    /**
     *  Locate an attribute in one of the attribute buckets  The buckets are
     *  searched in the order protected, unprotected, unsent.
     * 
     * @param label - Label of the value to be searched for
     * @return - CBORObject with the value if found; otherwise null
     */
    public CBORObject findAttribute(CBORObject label) {
        return findAttribute(label, PROTECTED | UNPROTECTED | DO_NOT_SEND);
    }
    
    /**
     *  Locate an attribute in one of the attribute buckets  The buckets are
     *  searched in the order protected, unprotected, unsent.
     * 
     * @param label - HeaderKey enumeration value to search for
     * @param where which maps to search for the label
     * @return - CBORObject with the value if found; otherwise null
     */
    public CBORObject findAttribute(CBORObject label, int where) {
        if (((where & PROTECTED) == PROTECTED) && objProtected.ContainsKey(label)) return objProtected.get(label);
        if (((where & UNPROTECTED) == UNPROTECTED) && objUnprotected.ContainsKey(label)) return objUnprotected.get(label);
        if (((where & DO_NOT_SEND) == DO_NOT_SEND) && objDontSend.ContainsKey(label)) return objDontSend.get(label);
        return null;
    }
    
    /**
     *  Locate an attribute in one of the attribute buckets  The buckets are
     *  searched in the order protected, unprotected, unsent.
     * 
     * @param label - HeaderKey enumeration value to search for
     * @return - CBORObject with the value if found; otherwise null
     */
    public CBORObject findAttribute(HeaderKeys label) {
        return findAttribute(label.AsCBOR(), PROTECTED | UNPROTECTED | DO_NOT_SEND);
    }
    
    /**
     *  Locate an attribute in one of the attribute buckets  The buckets are
     *  searched in the order protected, unprotected, unsent.
     * 
     * @param label - HeaderKey enumeration value to search for
     * @param where which maps to search for the label
     * @return - CBORObject with the value if found; otherwise null
     */
    public CBORObject findAttribute(HeaderKeys label, int where) {
        return findAttribute(label.AsCBOR(), where);
    }
    
    /**
     * Return the entire map of protected attributes
     * 
     * @return the protected attribute map
     */
    public CBORObject getProtectedAttributes() {
        return objProtected;
    }
    
    /**
     * Return the entire map of unprotected attributes
     * 
     * @return the unprotected attribute map
     */
    public CBORObject getUnprotectedAttributes() {
        return objUnprotected;
    }

    /**
     * Return the entire map of do not send attributes
     * 
     * @return the do not send attribute map
     */
    public CBORObject getDoNotSendAttributes() {
        return objDontSend;
    }

    /**
     * Remove an attribute from the set of all attribute maps.
     * 
     * @param label attribute to be removed
     * @exception CoseException if integrity protection would be modified.
     */
    public void removeAttribute(CBORObject label) throws CoseException {
        if (objProtected.ContainsKey(label)) {
            if (rgbProtected != null) throw new CoseException("Operation would modify integrity protected attributes");
            objProtected.Remove(label);
        }
        if (objUnprotected.ContainsKey(label)) objUnprotected.Remove(label);
        if (objDontSend.ContainsKey(label)) objDontSend.Remove(label);
    }
    
    /**
     * Remove an attribute from the set of all attribute maps.
     * 
     * @param label attribute to be removed
     * @throws CoseException - Label not present
     */
    public void removeAttribute(HeaderKeys label) throws CoseException {
        removeAttribute(label.AsCBOR());
    }
    
    /**
     * Get the optional external data field to be authenticated
     * 
     * @return external authenticated data
     */
    public byte[] getExternal() {
        return externalData;
    }
    
    /**
     * Set the optional external data field to be authenticated
     * 
     * @param rgbData - data to be authenticated
     */
    public void setExternal(byte[] rgbData) {
        if (rgbData == null) rgbData = new byte[0];
        externalData = rgbData;
    }                
}
