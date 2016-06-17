/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

package com.southernstorm.noise.protocol;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implements the "AESGCM" cipher for Noise using JCA/JCE.
 */
class AESGCMCipherState implements CipherState {
	
	private Cipher cipher;
	private SecretKeySpec keySpec;
	private long n;
	private byte[] nf;

	/**
	 * Constructs a new cipher state for the "AESGCM" algorithm.
	 * 
	 * @throws NoSuchAlgorithmException The system does not have a
	 * provider for this algorithm.
	 */
	public AESGCMCipherState() throws NoSuchAlgorithmException
	{
		try {
			cipher = Cipher.getInstance("AES/GCM/NoPadding");
		} catch (NoSuchPaddingException e) {
			// AES/GCM is available, but not the unpadded version?  Huh?
			throw new NoSuchAlgorithmException("AES/GCM/NoPadding not available", e);
		}
		keySpec = null;
		n = 0;
		nf = new byte [12];
	}

	@Override
	public void destroy() {
		// There doesn't seem to be a standard API to clean out a Cipher.
		// So we instead set the key and IV to all-zeroes to hopefully
		// destroy the sensitive data in the cipher instances.
		keySpec = new SecretKeySpec(new byte [32], "AES");
		GCMParameterSpec params = new GCMParameterSpec(128, new byte [12]);
		try {
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);
		} catch (InvalidKeyException e) {
			// Shouldn't happen.
		} catch (InvalidAlgorithmParameterException e) {
			// Shouldn't happen.
		}
	}

	@Override
	public String getCipherName() {
		return "AESGCM";
	}

	@Override
	public int getKeyLength() {
		return 32;
	}

	@Override
	public int getMACLength() {
		return keySpec != null ? 32 : 0;
	}

	/**
	 * Creates a GCM parameter block for a new packet encrypt/decrypt operation.
	 * 
	 * @return The GCM parameters for the current nonce.
	 */
	private GCMParameterSpec createGCMParams()
	{
		nf[0] = (byte)0;
		nf[1] = (byte)0;
		nf[2] = (byte)0;
		nf[3] = (byte)0;
		nf[4] = (byte)(n >> 56);
		nf[5] = (byte)(n >> 48);
		nf[6] = (byte)(n >> 40);
		nf[7] = (byte)(n >> 32);
		nf[8] = (byte)(n >> 24);
		nf[9] = (byte)(n >> 16);
		nf[10] = (byte)(n >> 8);
		nf[11] = (byte)n;
		++n;
		return new GCMParameterSpec(128, nf);
	}

	@Override
	public void initializeKey(byte[] key, int offset) {
		keySpec = new SecretKeySpec(key, offset, 32, "AES");
		n = 0;
	}

	@Override
	public boolean hasKey() {
		return keySpec != null;
	}

	@Override
	public int encryptWithAd(byte[] ad, byte[] plaintext, int plaintextOffset,
			byte[] ciphertext, int ciphertextOffset, int length) {
		if (keySpec == null) {
			// The key is not set yet - return the plaintext as-is.
			if (plaintext != ciphertext || plaintextOffset != ciphertextOffset)
				System.arraycopy(plaintext, plaintextOffset, ciphertext, ciphertextOffset, length);
			return length;
		}
		try {
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, createGCMParams());
		} catch (InvalidKeyException e) {
			// Shouldn't happen.
			return -1;
		} catch (InvalidAlgorithmParameterException e) {
			// Shouldn't happen.
			return -1;
		}
		if (ad != null)
			cipher.updateAAD(ad);
		try {
			int result = cipher.update(plaintext, plaintextOffset, length, ciphertext, ciphertextOffset);
			result += cipher.doFinal(ciphertext, ciphertextOffset + result);
			return result;
		} catch (ShortBufferException e) {
			return -1;
		} catch (IllegalBlockSizeException e) {
			return -1;
		} catch (BadPaddingException e) {
			return -1;
		}
	}

	@Override
	public int decryptWithAd(byte[] ad, byte[] ciphertext,
			int ciphertextOffset, byte[] plaintext, int plaintextOffset,
			int length) {
		if (keySpec == null) {
			// The key is not set yet - return the ciphertext as-is.
			if (plaintext != ciphertext || plaintextOffset != ciphertextOffset)
				System.arraycopy(ciphertext, ciphertextOffset, plaintext, plaintextOffset, length);
			return length;
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, keySpec, createGCMParams());
		} catch (InvalidKeyException e) {
			// Shouldn't happen.
			return -1;
		} catch (InvalidAlgorithmParameterException e) {
			// Shouldn't happen.
			return -1;
		}
		if (ad != null)
			cipher.updateAAD(ad);
		try {
			int result = cipher.update(ciphertext, ciphertextOffset, length, plaintext, plaintextOffset);
			result += cipher.doFinal(plaintext, plaintextOffset + result);
			return result;
		} catch (ShortBufferException e) {
			return -1;
		} catch (IllegalBlockSizeException e) {
			return -1;
		} catch (BadPaddingException e) {
			return -1;
		}
	}

	@Override
	public CipherState fork(byte[] key, int offset) {
		CipherState cipher;
		try {
			cipher = new AESGCMCipherState();
		} catch (NoSuchAlgorithmException e) {
			// Shouldn't happen.
			return null;
		}
		cipher.initializeKey(key, offset);
		return cipher;
	}
}
