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

import java.lang.reflect.InvocationTargetException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implements the "AESGCM" cipher for Noise using JCA/JCE.
 */
class AESGCMCipherState implements CipherState {
	
	private Cipher cipher;
	private SecretKeySpec keySpec;
	private long n;
	private byte[] nf;
	private Class<?> gcmClass;

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
		try {
			gcmClass = Class.forName("javax.crypto.spec.GCMParameterSpec");
		} catch (ClassNotFoundException e) {
			gcmClass = null;
		}
		
		// Try to set a 256-bit key on the cipher.  Some JCE's are
		// configured to disallow 256-bit AES if an extra policy
		// file has not been installed.
		try {
			SecretKeySpec spec = new SecretKeySpec(new byte [32], "AES");
			AlgorithmParameterSpec params = createGCMParams();
			cipher.init(Cipher.ENCRYPT_MODE, spec, params);
		} catch (InvalidKeyException e) {
			throw new NoSuchAlgorithmException("AES/GCM/NoPadding does not support 256-bit keys", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new NoSuchAlgorithmException("AES/GCM/NoPadding does not support 256-bit keys", e);
		} finally {
			n = 0;
		}
	}

	@Override
	public void destroy() {
		// There doesn't seem to be a standard API to clean out a Cipher.
		// So we instead set the key and IV to all-zeroes to hopefully
		// destroy the sensitive data in the cipher instances.
		keySpec = new SecretKeySpec(new byte [32], "AES");
		n = 0;
		try {
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, createGCMParams());
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
		return keySpec != null ? 16 : 0;
	}

	/**
	 * Creates a GCM parameter block for a new packet encrypt/decrypt operation.
	 * 
	 * @return The GCM parameters for the current nonce.
	 */
	private AlgorithmParameterSpec createGCMParams()
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
		if (gcmClass != null) {
			// Equivalent of "return new GCMParameterSpec(128, nf)" without
			// linking against GCMParameterSpec at compile time, which doesn't
			// exist in older JDK's.
			try {
				return (AlgorithmParameterSpec)gcmClass.getConstructor(int.class, byte[].class).newInstance(128, nf);
			} catch (NoSuchMethodException e) {
			} catch (SecurityException e) {
			} catch (InstantiationException e) {
			} catch (IllegalAccessException e) {
			} catch (IllegalArgumentException e) {
			} catch (InvocationTargetException e) {
			}
		}
		return null;
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
			byte[] ciphertext, int ciphertextOffset, int length) throws ShortBufferException {
		int space;
		if (ciphertextOffset > ciphertext.length)
			space = 0;
		else
			space = ciphertext.length - ciphertextOffset;
		if (keySpec == null) {
			// The key is not set yet - return the plaintext as-is.
			if (length > space)
				throw new ShortBufferException();
			if (plaintext != ciphertext || plaintextOffset != ciphertextOffset)
				System.arraycopy(plaintext, plaintextOffset, ciphertext, ciphertextOffset, length);
			return length;
		}
		if (space < 16 || length > (space - 16))
			throw new ShortBufferException();
		if (n < 0)
			throw new IllegalStateException("Nonce has wrapped around");
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
		} catch (IllegalBlockSizeException e) {
			return -1;
		} catch (BadPaddingException e) {
			return -1;
		}
	}

	@Override
	public int decryptWithAd(byte[] ad, byte[] ciphertext,
			int ciphertextOffset, byte[] plaintext, int plaintextOffset,
			int length) throws ShortBufferException, BadPaddingException {
		int space;
		if (ciphertextOffset > ciphertext.length)
			space = 0;
		else
			space = ciphertext.length - ciphertextOffset;
		if (length > space)
			throw new ShortBufferException();
		if (plaintextOffset > plaintext.length)
			space = 0;
		else
			space = plaintext.length - plaintextOffset;
		if (keySpec == null) {
			// The key is not set yet - return the ciphertext as-is.
			if (plaintext != ciphertext || plaintextOffset != ciphertextOffset)
				System.arraycopy(ciphertext, ciphertextOffset, plaintext, plaintextOffset, length);
			return length;
		}
		if (length < 16)
			Noise.throwBadTagException();
		int dataLen = length - 16;
		if (dataLen > space)
			throw new ShortBufferException();
		if (n < 0)
			throw new IllegalStateException("Nonce has wrapped around");
		try {
			cipher.init(Cipher.DECRYPT_MODE, keySpec, createGCMParams());
		} catch (InvalidKeyException e) {
			// Shouldn't happen.
			Noise.throwBadTagException();
		} catch (InvalidAlgorithmParameterException e) {
			// Shouldn't happen.
			Noise.throwBadTagException();
		}
		if (ad != null)
			cipher.updateAAD(ad);
		try {
			int result = cipher.update(ciphertext, ciphertextOffset, length, plaintext, plaintextOffset);
			result += cipher.doFinal(plaintext, plaintextOffset + result);
			return result;
		} catch (IllegalBlockSizeException e) {
			Noise.throwBadTagException();
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

	@Override
	public void setNonce(long nonce) {
		if (nonce < n)
			throw new IllegalArgumentException("Nonce values cannot go backwards");
		n = nonce;
	}
}
