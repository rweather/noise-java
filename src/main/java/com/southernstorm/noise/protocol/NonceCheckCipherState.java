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

import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;

/**
 * A CipherState implementation that checks
 * the nonce not to be the reserved <code>rekey()</code>
 * value on encrypt and decrypt.
 */
public final class NonceCheckCipherState implements CipherState {
	private final CipherState delegate;

	public NonceCheckCipherState(CipherState delegate) {
		this.delegate = delegate;
	}

	@Override
	public String getCipherName() {
		return delegate.getCipherName();
	}

	@Override
	public int getKeyLength() {
		return delegate.getKeyLength();
	}
	
	@Override
	public int getMACLength() {
		return delegate.getMACLength();
	}

	@Override
	public void initializeKey(byte[] key, int offset) {
		delegate.initializeKey(key, offset);
	}

	@Override
	public boolean hasKey() {
		return delegate.hasKey();
	}
	
	@Override
	public int encryptWithAd(byte[] ad, byte[] plaintext, int plaintextOffset, byte[] ciphertext, int ciphertextOffset, int length) throws ShortBufferException {
		// Check for nonce wrap-around.
		if (getNonce() == -1L)
			throw new IllegalStateException("Nonce has wrapped around");
		
		return delegate.encryptWithAd(ad, plaintext, plaintextOffset, ciphertext, ciphertextOffset, length);
	}

	@Override
	public int decryptWithAd(byte[] ad, byte[] ciphertext, int ciphertextOffset, byte[] plaintext, int plaintextOffset, int length) throws ShortBufferException, BadPaddingException {
		// Check for nonce wrap-around.
		if (getNonce() == -1L)
			throw new IllegalStateException("Nonce has wrapped around");
		
		return delegate.decryptWithAd(ad, ciphertext, ciphertextOffset, plaintext, plaintextOffset, length);
	}

	@Override
	public CipherState fork(byte[] key, int offset) {
		return delegate.fork(key, offset);
	}
	
	@Override
	public void setNonce(long nonce) {
		delegate.setNonce(nonce);
	}

	@Override
	public long getNonce() {
       return delegate.getNonce();
   }

	@Override
	public void rekey() throws ShortBufferException {
       delegate.rekey();
   }

	@Override
	public void destroy() {
		delegate.destroy();
	}
}
