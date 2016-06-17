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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Utility functions for the Noise protocol library.
 */
public final class Noise {

	/**
	 * Destroys the contents of a byte array.
	 * 
	 * @param array The array whose contents should be destroyed.
	 */
	public static void destroy(byte[] array)
	{
		Arrays.fill(array, (byte)0);
	}
	
	/**
	 * Creates a cipher object from its Noise protocol name.
	 * 
	 * @param name The name of the cipher algorithm; e.g. "AESGCM", "ChaChaPoly", etc.
	 * 
	 * @return The cipher object if the name is recognized.
	 * 
	 * @throws NoSuchAlgorithmException The name is not recognized as a
	 * valid Noise protocol name, or there is no cryptography provider
	 * in the system that implements the algorithm.
	 */
	public static CipherState createCipher(String name) throws NoSuchAlgorithmException
	{
		if (name.equals("AESGCM"))
			return new AESGCMCipherState();
		throw new NoSuchAlgorithmException("Unknown Noise cipher algorithm name: " + name);
	}
	
	/**
	 * Creates a hash object from its Noise protocol name.
	 * 
	 * @param name The name of the hash algorithm; e.g. "SHA256", "BLAKE2s", etc.
	 * 
	 * @return The hash object if the name is recognized.
	 * 
	 * @throws NoSuchAlgorithmException The name is not recognized as a
	 * valid Noise protocol name, or there is no cryptography provider
	 * in the system that implements the algorithm.
	 */
	public static MessageDigest createHash(String name) throws NoSuchAlgorithmException
	{
		// The SHA-256 and SHA-512 names are fairly common in standard JDK's.
		// The BLAKE2 algorithms will need the installation of a third-party
		// cryptography provider like Bouncy Castle.
		if (name.equals("SHA256"))
			return MessageDigest.getInstance("SHA-256");
		else if (name.equals("SHA512"))
			return MessageDigest.getInstance("SHA-512");
		else if (name.equals("BLAKE2b"))
			return MessageDigest.getInstance("Blake2b");
		else if (name.equals("BLAKE2s"))
			return MessageDigest.getInstance("Blake2s");
		throw new NoSuchAlgorithmException("Unknown Noise hash algorithm name: " + name);
	}
}
