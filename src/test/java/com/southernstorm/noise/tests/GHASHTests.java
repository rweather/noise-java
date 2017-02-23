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

import com.southernstorm.noise.crypto.GHASH;

public class GHASHTests {

	private void testGHASH(String key, String data, String hash)
	{
		byte[] keyBytes = TestUtils.stringToData(key);
		byte[] dataBytes = TestUtils.stringToData(data);
		byte[] hashBytes = TestUtils.stringToData(hash);
		byte[] tag = new byte [16];
		
		GHASH ghash = new GHASH();
		ghash.reset(keyBytes, 0);
		ghash.update(dataBytes, 0, dataBytes.length);
		Arrays.fill(tag, (byte)0xAA);
		ghash.finish(tag, 0, 16);
		assertArrayEquals(hashBytes, tag);

		ghash.reset();
		ghash.update(dataBytes, 0, dataBytes.length / 3);
		ghash.update(dataBytes, dataBytes.length / 3, dataBytes.length - (dataBytes.length / 3));
		Arrays.fill(tag, (byte)0xAA);
		ghash.finish(tag, 0, 16);
		assertArrayEquals(hashBytes, tag);
	}

	@Test
	public void ghash() {
		// Test vectors from Appendix B of:
		// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
		
		testGHASH("0x66e94bd4ef8a2c3b884cfa59ca342b2e",
				  "0x00000000000000000000000000000000",
				  "0x00000000000000000000000000000000");
		
		testGHASH("0x66e94bd4ef8a2c3b884cfa59ca342b2e",
				  "0x0388dace60b6a392f328c2b971b2fe7800000000000000000000000000000080",
				  "0xf38cbb1ad69223dcc3457ae5b6b0f885");
		
		testGHASH("0xb83b533708bf535d0aa6e52980d53b78",
				  "0x42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f598500000000000000000000000000000200",
				  "0x7f1b32b81b820d02614f8895ac1d4eac");
		
		testGHASH("0xb83b533708bf535d0aa6e52980d53b78",
				  "0xfeedfacedeadbeeffeedfacedeadbeefabaddad200000000000000000000000042831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0910000000000000000000000a000000000000001e0",
				  "0x698e57f70e6ecc7fd9463b7260a9ae5f");
	}
}
