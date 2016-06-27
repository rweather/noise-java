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

import com.southernstorm.noise.crypto.Curve25519;

public class Curve25519Tests {

	@Test
	public void curve25519() {
		// Test vectors from section 6.1 of RFC 7748.
		byte[] alicePrivate = TestUtils.stringToData("0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
		byte[] alicePublic  = TestUtils.stringToData("0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
		byte[] bobPrivate   = TestUtils.stringToData("0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
		byte[] bobPublic    = TestUtils.stringToData("0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
		byte[] sharedSecret = TestUtils.stringToData("0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
		byte[] output = new byte [32];
		
		// Test derivation of public keys from private keys.
		Arrays.fill(output, (byte)0xAA);
		Curve25519.eval(output, 0, alicePrivate, null);
		assertArrayEquals(alicePublic, output);
		Arrays.fill(output, (byte)0xAA);
		Curve25519.eval(output, 0, bobPrivate, null);
		assertArrayEquals(bobPublic, output);
		
		// Test creation of the shared secret in both directions.
		Arrays.fill(output, (byte)0xAA);
		Curve25519.eval(output, 0, alicePrivate, bobPublic);
		assertArrayEquals(sharedSecret, output);
		Arrays.fill(output, (byte)0xAA);
		Curve25519.eval(output, 0, bobPrivate, alicePublic);
		assertArrayEquals(sharedSecret, output);
	}

}
