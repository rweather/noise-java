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

import com.southernstorm.noise.crypto.Poly1305;

/**
 * Perform tests on the Poly1305 implementation in isolation from ChaChaPoly.
 */
public class Poly1305Tests {

	private void testPoly1305(String key, String data, String hash)
	{
		byte[] keyBytes = TestUtils.stringToData(key);
		byte[] dataBytes = TestUtils.stringToData(data);
		byte[] hashBytes = TestUtils.stringToData(hash);
		byte[] token = new byte [16];

		// Authenticate the data in one hit.
		Poly1305 poly = new Poly1305();
		poly.reset(keyBytes, 0);
		poly.update(dataBytes, 0, dataBytes.length);
		poly.finish(token, 0);
		assertArrayEquals(hashBytes, token);
		
		// Break the data up into chunks to test multiple calls to update().
		Arrays.fill(token, (byte)0xDD);
		poly.reset(keyBytes, 0);
		poly.update(dataBytes, 0, dataBytes.length / 2);
		poly.update(dataBytes, dataBytes.length / 2, dataBytes.length - (dataBytes.length / 2));
		poly.finish(token, 0);
		assertArrayEquals(hashBytes, token);
	}

	@Test
	public void poly1305() {
		// Test vectors from the Poly1305 specification.
		testPoly1305("0x851fc40c3467ac0be05cc20404f3f700580b3b0f9447bb1e69d095b5928b6dbc", "0xf3f6", "0xf4c633c3044fc145f84f335cb81953de");
		testPoly1305("0xa0f3080000f46400d0c7e9076c834403dd3fab2251f11ac759f0887129cc2ee7", "", "0xdd3fab2251f11ac759f0887129cc2ee7");
		testPoly1305("0x48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef", "0x663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136", "0x0ee1c16bb73f0f4fd19881753c01cdbe");
		testPoly1305("0x12976a08c4426d0ce8a82407c4f4820780f8c20aa71202d1e29179cbcb555a57", "0xab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9", "0x5154ad0d2cb26e01274fc51148491f1b");
	}

}
