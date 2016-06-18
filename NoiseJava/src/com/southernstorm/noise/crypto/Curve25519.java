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

package com.southernstorm.noise.crypto;

/**
 * Implementation of the Curve25519 elliptic-curve algorithm.
 */
public final class Curve25519 {

	private Curve25519() {}
	
	/**
	 * Evaluates the Curve25519 curve.
	 * 
	 * @param result Buffer to place the result of the evaluation into.
	 * @param offset Offset into the result buffer.
	 * @param privateKey The private key to use in the evaluation.
	 * @param publicKey The public key to use in the evaluation, or null
	 * if the base point of the curve should be used.
	 */
	public static void eval(byte[] result, int offset, byte[] privateKey, byte[] publicKey)
	{
		// TODO
	}
}
