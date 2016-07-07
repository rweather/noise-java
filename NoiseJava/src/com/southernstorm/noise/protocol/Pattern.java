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
 * Information about all supported handshake patterns.
 */
class Pattern {
	
	private Pattern() {}

	// Token codes.
	public static final byte S = 1;
	public static final byte E = 2;
	public static final byte DHEE = 3;
	public static final byte DHES = 4;
	public static final byte DHSE = 5;
	public static final byte DHSS = 6;
	public static final byte FLIP_DIR = 7;
	
	// Pattern flag bits.
	public static final byte FLAG_LOCAL_STATIC = 0x01;
	public static final byte FLAG_LOCAL_EPHEMERAL = 0x02;
	public static final byte FLAG_LOCAL_REQUIRED = 0x04;
	public static final byte FLAG_LOCAL_EPHEM_REQ = 0x08;
	public static final byte FLAG_REMOTE_STATIC = 0x10;
	public static final byte FLAG_REMOTE_EPHEMERAL = 0x20;
	public static final byte FLAG_REMOTE_REQUIRED = 0x40;
	public static final byte FLAG_REMOTE_EPHEM_REQ = (byte)0x80;

	private static final byte[] noise_pattern_N = {
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_REQUIRED,

	    E,
	    DHES
	};

	private static final byte[] noise_pattern_K = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_LOCAL_REQUIRED |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_REQUIRED,

	    E,
	    DHES,
	    DHSS
	};

	private static final byte[] noise_pattern_X = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_REQUIRED,

	    E,
	    DHES,
	    S,
	    DHSS
	};

	private static final byte[] noise_pattern_NN = {
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_EPHEMERAL,

	    E,
	    FLIP_DIR,
	    E,
	    DHEE
	};

	private static final byte[] noise_pattern_NK = {
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL |
	    FLAG_REMOTE_REQUIRED,

	    E,
	    DHES,
	    FLIP_DIR,
	    E,
	    DHEE
	};

	private static final byte[] noise_pattern_NX = {
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL,

	    E,
	    FLIP_DIR,
	    E,
	    DHEE,
	    S,
	    DHSE
	};

	private static final byte[] noise_pattern_XN = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_EPHEMERAL,

	    E,
	    FLIP_DIR,
	    E,
	    DHEE,
	    FLIP_DIR,
	    S,
	    DHSE
	};

	private static final byte[] noise_pattern_XK = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL |
	    FLAG_REMOTE_REQUIRED,

	    E,
	    DHES,
	    FLIP_DIR,
	    E,
	    DHEE,
	    FLIP_DIR,
	    S,
	    DHSE
	};

	private static final byte[] noise_pattern_XX = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL,

	    E,
	    FLIP_DIR,
	    E,
	    DHEE,
	    S,
	    DHSE,
	    FLIP_DIR,
	    S,
	    DHSE
	};

	private static final byte[] noise_pattern_KN = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_LOCAL_REQUIRED |
	    FLAG_REMOTE_EPHEMERAL,

	    E,
	    FLIP_DIR,
	    E,
	    DHEE,
	    DHES
	};

	private static final byte[] noise_pattern_KK = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_LOCAL_REQUIRED |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL |
	    FLAG_REMOTE_REQUIRED,

	    E,
	    DHES,
	    DHSS,
	    FLIP_DIR,
	    E,
	    DHEE,
	    DHES
	};

	private static final byte[] noise_pattern_KX = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_LOCAL_REQUIRED |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL,

	    E,
	    FLIP_DIR,
	    E,
	    DHEE,
	    DHES,
	    S,
	    DHSE
	};

	private static final byte[] noise_pattern_IN = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_EPHEMERAL,

	    E,
	    S,
	    FLIP_DIR,
	    E,
	    DHEE,
	    DHES
	};

	private static final byte[] noise_pattern_IK = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL |
	    FLAG_REMOTE_REQUIRED,

	    E,
	    DHES,
	    S,
	    DHSS,
	    FLIP_DIR,
	    E,
	    DHEE,
	    DHES
	};

	private static final byte[] noise_pattern_IX = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL,

	    E,
	    S,
	    FLIP_DIR,
	    E,
	    DHEE,
	    DHES,
	    S,
	    DHSE
	};

	private static final byte[] noise_pattern_XXfallback = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL |
	    FLAG_REMOTE_EPHEM_REQ,

	    E,
	    DHEE,
	    S,
	    DHSE,
	    FLIP_DIR,
	    S,
	    DHSE
	};

	private static final byte[] noise_pattern_NXfallback = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_EPHEMERAL |
	    FLAG_REMOTE_EPHEM_REQ,

	    E,
	    DHEE,
	    S,
	    DHSE
	};

	private static final byte[] noise_pattern_IXfallback = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL |
	    FLAG_REMOTE_REQUIRED |
	    FLAG_REMOTE_EPHEM_REQ,

	    E,
	    DHEE,
	    DHES,
	    S,
	    DHSE
	};

	private static final byte[] noise_pattern_Xnoidh = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_REQUIRED,

	    E,
	    S,
	    DHES,
	    DHSS
	};

	private static final byte[] noise_pattern_NXnoidh = {
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL,

	    E,
	    FLIP_DIR,
	    E,
	    S,
	    DHEE,
	    DHSE
	};

	private static final byte[] noise_pattern_XXnoidh = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL,

	    E,
	    FLIP_DIR,
	    E,
	    S,
	    DHEE,
	    DHSE,
	    FLIP_DIR,
	    S,
	    DHSE
	};

	private static final byte[] noise_pattern_KXnoidh = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_LOCAL_REQUIRED |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL,

	    E,
	    FLIP_DIR,
	    E,
	    S,
	    DHEE,
	    DHES,
	    DHSE
	};

	private static final byte[] noise_pattern_IKnoidh = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL |
	    FLAG_REMOTE_REQUIRED,

	    E,
	    S,
	    DHES,
	    DHSS,
	    FLIP_DIR,
	    E,
	    DHEE,
	    DHES
	};

	private static final byte[] noise_pattern_IXnoidh = {
	    FLAG_LOCAL_STATIC |
	    FLAG_LOCAL_EPHEMERAL |
	    FLAG_REMOTE_STATIC |
	    FLAG_REMOTE_EPHEMERAL,

	    E,
	    S,
	    FLIP_DIR,
	    E,
	    S,
	    DHEE,
	    DHES,
	    DHSE
	};

	/**
	 * Look up the description information for a pattern.
	 * 
	 * @param name The name of the pattern.
	 * @return The pattern description or null.
	 */
	public static byte[] lookup(String name)
	{
		if (name.equals("N"))
			return noise_pattern_N;
		else if (name.equals("K"))
			return noise_pattern_K;
		else if (name.equals("X"))
			return noise_pattern_X;
		else if (name.equals("NN"))
			return noise_pattern_NN;
		else if (name.equals("NK"))
			return noise_pattern_NK;
		else if (name.equals("NX"))
			return noise_pattern_NX;
		else if (name.equals("XN"))
			return noise_pattern_XN;
		else if (name.equals("XK"))
			return noise_pattern_XK;
		else if (name.equals("XX"))
			return noise_pattern_XX;
		else if (name.equals("KN"))
			return noise_pattern_KN;
		else if (name.equals("KK"))
			return noise_pattern_KK;
		else if (name.equals("KX"))
			return noise_pattern_KX;
		else if (name.equals("IN"))
			return noise_pattern_IN;
		else if (name.equals("IK"))
			return noise_pattern_IK;
		else if (name.equals("IX"))
			return noise_pattern_IX;
		else if (name.equals("XXfallback"))
			return noise_pattern_XXfallback;
		else if (name.equals("NXfallback"))
			return noise_pattern_NXfallback;
		else if (name.equals("IXfallback"))
			return noise_pattern_IXfallback;
		else if (name.equals("Xnoidh"))
			return noise_pattern_Xnoidh;
		else if (name.equals("NXnoidh"))
			return noise_pattern_NXnoidh;
		else if (name.equals("XXnoidh"))
			return noise_pattern_XXnoidh;
		else if (name.equals("KXnoidh"))
			return noise_pattern_KXnoidh;
		else if (name.equals("IKnoidh"))
			return noise_pattern_IKnoidh;
		else if (name.equals("IXnoidh"))
			return noise_pattern_IXnoidh;
		return null;
	}

	/**
	 * Reverses the local and remote flags for a pattern.
	 * 
	 * @param flags The flags, assuming that the initiator is "local".
	 * @return The reversed flags, with the responder now being "local".
	 */
	public static byte reverseFlags(byte flags)
	{
		return (byte)(((flags >> 4) & 0x0F) | ((flags << 4) & 0xF0));
	}
}
