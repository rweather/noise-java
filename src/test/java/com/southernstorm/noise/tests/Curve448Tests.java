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

import com.southernstorm.noise.crypto.Curve448;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

public class Curve448Tests {

	@Test
	public void curve448() {
		// Test vectors from section 6.2 of RFC 7748.
		byte[] alicePrivate = TestUtils.stringToData("0x9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
		byte[] alicePublic  = TestUtils.stringToData("0x9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
		byte[] bobPrivate   = TestUtils.stringToData("0x1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
		byte[] bobPublic    = TestUtils.stringToData("0x3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
		byte[] sharedSecret = TestUtils.stringToData("0x07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");
		byte[] output = new byte [56];
		
		// Test derivation of public keys from private keys.
		Arrays.fill(output, (byte)0xAA);
		Curve448.eval(output, 0, alicePrivate, null);
		assertArrayEquals(alicePublic, output);
		Arrays.fill(output, (byte)0xAA);
		Curve448.eval(output, 0, bobPrivate, null);
		assertArrayEquals(bobPublic, output);
		
		// Test creation of the shared secret in both directions.
		Arrays.fill(output, (byte)0xAA);
		Curve448.eval(output, 0, alicePrivate, bobPublic);
		assertArrayEquals(sharedSecret, output);
		Arrays.fill(output, (byte)0xAA);
		Curve448.eval(output, 0, bobPrivate, alicePublic);
		assertArrayEquals(sharedSecret, output);
	}

}
