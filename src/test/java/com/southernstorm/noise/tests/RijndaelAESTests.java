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

import java.util.Arrays;

import org.junit.Test;

import com.southernstorm.noise.crypto.RijndaelAES;

/**
 * AES test cases to verify the fallback RijndaelAES implementation.
 */
public class RijndaelAESTests {

	private void testECB(String key, String plaintext, String ciphertext)
	{
		byte[] keyBytes = TestUtils.stringToData(key);
		byte[] plaintextBytes = TestUtils.stringToData(plaintext);
		byte[] ciphertextBytes = TestUtils.stringToData(ciphertext);
		byte[] block = new byte [16];
		
		RijndaelAES aes = new RijndaelAES();
		
		Arrays.fill(block, (byte)0xAA);
		aes.setupEnc(keyBytes, 0, keyBytes.length * 8);
		aes.encrypt(plaintextBytes, 0, block, 0);
		assertArrayEquals(ciphertextBytes, block);

		Arrays.fill(block, (byte)0xAA);
		aes.setupDec(keyBytes, 0, keyBytes.length * 8);
		aes.decrypt(ciphertextBytes, 0, block, 0);
		assertArrayEquals(plaintextBytes, block);
		
		aes.destroy();
	}

	@Test
	public void rijndael()
	{
		// ECB test vectors from the FIPS specification.
		testECB("0x000102030405060708090A0B0C0D0E0F", "0x00112233445566778899AABBCCDDEEFF", "0x69C4E0D86A7B0430D8CDB78070B4C55A");
		testECB("0x000102030405060708090A0B0C0D0E0F1011121314151617", "0x00112233445566778899AABBCCDDEEFF", "0xDDA97CA4864CDFE06EAF70A0EC0D7191");
		testECB("0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "0x00112233445566778899AABBCCDDEEFF", "0x8EA2B7CA516745BFEAFC49904B496089");
	}
}
