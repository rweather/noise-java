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

/**
 * Interface to a cryptographic hash algorithm.
 */
public interface HashState extends Destroyable {

	/**
	 * Gets the length of the hash output for this algorithm.
	 * 
	 * @return The length of the hash in bytes.
	 */
	int getHashLength();
	
	/**
	 * Gets the block length for this algorithm.
	 * 
	 * @return The length of the block in bytes.
	 */
	int getBlockLength();
	
	/**
	 * Resets the hash for a new hashing session.
	 */
	void reset();
	
	/**
	 * Updates the hash state with more data.
	 * 
	 * @param data Buffer containing the data.
	 * @param offset Offset into the data buffer of the first
	 * byte to be hashed.
	 * @param length Length of the region to be hashed.
	 */
	void update(byte[] data, int offset, int length);
	
	/**
	 * Finishes a hashing session and returns the output hash.
	 * 
	 * @param output Buffer to put the hash into.
	 * @param offset Offset of the first byte of the hash
	 * in the output buffer.
	 */
	void finish(byte[] output, int offset);
}
