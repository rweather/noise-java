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
 * Constants and utility functions for the Noise protocol library.
 */
public final class Noise {

	/**
	 * Handshake pattern identifier that indicates "no pattern".
	 */
	public static final int PATTERN_NONE = 0;
	/**
	 * Category for handshake patterns.
	 */
	public static final int PATTERN_CATEGORY = 0x5000;
	/**
	 * Handshake pattern identifier for "N".
	 */
	public static final int PATTERN_N = 0x5001;
	/**
	 * Handshake pattern identifier for "X".
	 */
	public static final int PATTERN_X = 0x5002;
	/**
	 * Handshake pattern identifier for "K".
	 */
	public static final int PATTERN_K = 0x5003;
	/**
	 * Handshake pattern identifier for "NN".
	 */
	public static final int PATTERN_NN = 0x5004;
	/**
	 * Handshake pattern identifier for "NK".
	 */
	public static final int PATTERN_NK = 0x5005;
	/**
	 * Handshake pattern identifier for "NX".
	 */
	public static final int PATTERN_NX = 0x5006;
	/**
	 * Handshake pattern identifier for "XN".
	 */
	public static final int PATTERN_XN = 0x5007;
	/**
	 * Handshake pattern identifier for "XK".
	 */
	public static final int PATTERN_XK = 0x5008;
	/**
	 * Handshake pattern identifier for "XX".
	 */
	public static final int PATTERN_XX = 0x5009;
	/**
	 * Handshake pattern identifier for "KN".
	 */
	public static final int PATTERN_KN = 0x500A;
	/**
	 * Handshake pattern identifier for "KK".
	 */
	public static final int PATTERN_KK = 0x500B;
	/**
	 * Handshake pattern identifier for "KX".
	 */
	public static final int PATTERN_KX = 0x500C;
	/**
	 * Handshake pattern identifier for "IN".
	 */
	public static final int PATTERN_IN = 0x500D;
	/**
	 * Handshake pattern identifier for "IK".
	 */
	public static final int PATTERN_IK = 0x500E;
	/**
	 * Handshake pattern identifier for "IX".
	 */
	public static final int PATTERN_IX = 0x500F;
	/**
	 * Handshake pattern identifier for "XXfallback".
	 */
	public static final int PATTERN_XX_FALLBACK = 0x5010;

	/**
	 * Destroys the contents of a byte array.
	 * 
	 * @param array The array whose contents should be destroyed.
	 */
	public static void destroy(byte[] array)
	{
		Arrays.fill(array, (byte)0);
	}
	
	public static CipherState createCipher(String name)
	{
		// TODO
		return null;
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
