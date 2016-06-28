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

package com.southernstorm.noise.tests;

import static org.junit.Assert.*;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;

import org.junit.Test;

import com.southernstorm.noise.protocol.CipherState;
import com.southernstorm.noise.protocol.Noise;

/**
 * Perform tests on the cipher algorithms used by Noise.
 */
public class CipherStateTests {

	private void testCipher(String name, int keyLen, int macLen,
							String key, long nonce, String ad,
							String plaintext, String ciphertext,
							String mac)
	{
		byte[] keyBytes = TestUtils.stringToData(key);
		byte[] adBytes = TestUtils.stringToData(ad);
		byte[] plaintextBytes = TestUtils.stringToData(plaintext);
		byte[] ciphertextBytes;
		byte[] buffer;
		if (ciphertext.length() > 0)
			ciphertextBytes = TestUtils.stringToData(ciphertext + mac.substring(2));
		else
			ciphertextBytes = TestUtils.stringToData(mac);

		// Create the cipher object and check its properties.
		CipherState cipher = null;
		try {
			cipher = Noise.createCipher(name);
		} catch (NoSuchAlgorithmException e) {
			fail(name + " cipher is not supported");
		}
		assertEquals(name, cipher.getCipherName());
		assertEquals(keyLen, cipher.getKeyLength());
		assertEquals(0, cipher.getMACLength()); // Key has not been set yet.
		
	    // Try to encrypt.  Because the key is not set yet, this will
	    // return the plaintext as-is.
		try {
			buffer = new byte [plaintextBytes.length];
			Arrays.fill(buffer, (byte)0xAA);
			assertEquals(plaintextBytes.length, cipher.encryptWithAd(adBytes, plaintextBytes, 0, buffer, 0, plaintextBytes.length));
			assertArrayEquals(plaintextBytes, buffer);
		} catch (ShortBufferException e) {
			fail("Buffer should have been big enough");
		}
		
		// Try to decrypt.  Will return the ciphertext and MAC as-is.
		buffer = new byte [ciphertextBytes.length];
		Arrays.fill(buffer, (byte)0xAA);
		try {
			assertEquals(ciphertextBytes.length, cipher.decryptWithAd(adBytes, ciphertextBytes, 0, buffer, 0, ciphertextBytes.length));
		} catch (BadPaddingException e) {
			fail();
		} catch (ShortBufferException e) {
			fail();
		}

		// Set the key and fast-forward the nonce.
		cipher.initializeKey(keyBytes, 0);
		cipher.setNonce(nonce);
		assertEquals(macLen, cipher.getMACLength());
		
		// Encrypt the data.
		try {
			buffer = new byte [ciphertextBytes.length];
			Arrays.fill(buffer, (byte)0xAA);
			assertEquals(ciphertextBytes.length, cipher.encryptWithAd(adBytes, plaintextBytes, 0, buffer, 0, plaintextBytes.length));
			assertArrayEquals(ciphertextBytes, buffer);
		} catch (ShortBufferException e) {
			fail("Buffer should have been big enough");
		}

	    // Try to decrypt.  The MAC check should fail because the internal
	    // nonce was incremented and no longer matches the parameter.
		try {
			cipher.decryptWithAd(adBytes, ciphertextBytes, 0, buffer, 0, ciphertextBytes.length);
			fail();
		} catch (BadPaddingException e) {
			// Success!
		} catch (ShortBufferException e) {
			fail();
		}
		
	    // Fast-forward the nonce to just before the rollover.  We will be able
	    // to encrypt one more block, and then the next request will be rejected.
		cipher.setNonce(0x7FFFFFFFFFFFFFFFL);
		try {
			buffer = new byte [ciphertextBytes.length];
			Arrays.fill(buffer, (byte)0xAA);
			cipher.encryptWithAd(adBytes, plaintextBytes, 0, buffer, 0, plaintextBytes.length);
			try {
				cipher.encryptWithAd(adBytes, plaintextBytes, 0, buffer, 0, plaintextBytes.length);
				fail();
			} catch (IllegalStateException e) {
				// Success!
			}
		} catch (ShortBufferException e) {
			fail("Buffer should have been big enough");
		}
		
		// Reset the key and then we can reset the nonce.
		cipher.initializeKey(keyBytes, 0);
		cipher.setNonce(nonce);
		assertEquals(macLen, cipher.getMACLength());
		
		// Decrypt the test ciphertext and MAC.
		try {
			buffer = new byte [plaintextBytes.length];
			Arrays.fill(buffer, (byte)0xAA);
			assertEquals(plaintextBytes.length, cipher.decryptWithAd(adBytes, ciphertextBytes, 0, buffer, 0, ciphertextBytes.length));
			assertArrayEquals(plaintextBytes, buffer);
		} catch (BadPaddingException e) {
			fail();
		} catch (ShortBufferException e) {
			fail();
		}

	    // Fast-forward the nonce to just before the rollover.  We will be able
	    // to decrypt one more block, and then the next request will be rejected.
		cipher.setNonce(0x7FFFFFFFFFFFFFFFL);
		try {
			buffer = new byte [plaintextBytes.length];
			Arrays.fill(buffer, (byte)0xAA);
			try {
				cipher.decryptWithAd(adBytes, ciphertextBytes, 0, buffer, 0, ciphertextBytes.length);
				fail();
			} catch (BadPaddingException e) {
				// Success!
			}
			try {
				cipher.decryptWithAd(adBytes, ciphertextBytes, 0, buffer, 0, ciphertextBytes.length);
				fail();
			} catch (IllegalStateException e) {
				// Success!
			} catch (BadPaddingException e) {
				fail();
			}
		} catch (ShortBufferException e) {
			fail("Buffer should have been big enough");
		}
	}

	@Test
	public void AESGCM() {
	    /* Test vectors for AES in GCM mode from Appendix B of:
	       http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	       We can only use a few of the vectors because most of the IV's in the
	       revised specification don't match what we need here */

	    // AESGCM - gcm-revised-spec.pdf, test case #13.
	    testCipher
	        ("AESGCM", 32, 16,
	         "0x0000000000000000000000000000000000000000000000000000000000000000",
	         0,
	         "",
	         "",
	         "",
	         "0x530f8afbc74536b9a963b4f1c4cb738b");

	    // AESGCM - gcm-revised-spec.pdf, test case #14.
	    testCipher
	        ("AESGCM", 32, 16,
	         "0x0000000000000000000000000000000000000000000000000000000000000000",
	         0,
	         "",
	         "0x00000000000000000000000000000000",
	         "0xcea7403d4d606b6e074ec5d3baf39d18",
	         "0xd0d1c8a799996bf0265b98b5d48ab919");
	}

	@Test
	public void ChaChaPoly() {
		// ChaChaPoly test vectors from Appendix A.5 of RFC 7539.
		testCipher
			("ChaChaPoly", 32, 16,
			 "0x1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
			 0x0807060504030201L,
			 "0xf33388860000000000004e91",
		     "0x496e7465726e65742d4472616674732061726520647261667420646f63756d65" +
	           "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d" +
	           "6f6e74687320616e64206d617920626520757064617465642c207265706c6163" +
	           "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65" +
	           "6e747320617420616e792074696d652e20497420697320696e617070726f7072" +
	           "6961746520746f2075736520496e7465726e65742d4472616674732061732072" +
	           "65666572656e6365206d6174657269616c206f7220746f206369746520746865" +
	           "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67" +
	           "726573732e2fe2809d",
	         "0x64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2" +
	           "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf" +
	           "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855" +
	           "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4" +
	           "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e" +
	           "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a" +
	           "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10" +
	           "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29" +
	           "a6ad5cb4022b02709b",
	         "0xeead9d67890cbb22392336fea1851f38");
	}
}
