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

import com.southernstorm.noise.protocol.Noise;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 * Perform tests on the hash algorithms used by Noise.
 */
public class HashTests {

	private void testHash(MessageDigest digest, String input, String hash)
	{
		byte[] inputBytes = TestUtils.stringToData(input);
		byte[] hashBytes = TestUtils.stringToData(hash);
		byte[] result = new byte [digest.getDigestLength()];
		
		// Hash the entire input in one request.
		digest.reset();
		digest.update(inputBytes);
		try {
			digest.digest(result, 0, result.length);
		} catch (DigestException e) {
			fail("digest failed");
		}
		assertArrayEquals(hashBytes, result);

		// Hash the input in pieces to test split requests.
		digest.reset();
		digest.update(inputBytes, 0, inputBytes.length / 2);
		digest.update(inputBytes, inputBytes.length / 2, inputBytes.length - (inputBytes.length / 2));
		try {
			digest.digest(result, 0, result.length);
		} catch (DigestException e) {
			fail("digest failed");
		}
		assertArrayEquals(hashBytes, result);
	}

	private void testHash(String name, String input, String hash)
	{
		MessageDigest digest = null;

		Noise.setForceFallbacks(true);
		try {
			digest = Noise.createHash(name);
		} catch (NoSuchAlgorithmException e) {
			fail("No crypto provider for " + name);
		} finally {
			Noise.setForceFallbacks(false);
		}
		testHash(digest, input, hash);

		Noise.setForceFallbacks(false);
		try {
			digest = Noise.createHash(name);
		} catch (NoSuchAlgorithmException e) {
			fail("No crypto provider for " + name);
		}
		testHash(digest, input, hash);
	}

	@Test
	public void blake2b() {
		testHash("BLAKE2b", "", "0x786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
		testHash("BLAKE2b", "abc", "0xba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
		testHash("BLAKE2b", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "0x7285ff3e8bd768d69be62b3bf18765a325917fa9744ac2f582a20850bc2b1141ed1b3e4528595acc90772bdf2d37dc8a47130b44f33a02e8730e5ad8e166e888");
		testHash("BLAKE2b", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "0xce741ac5930fe346811175c5227bb7bfcd47f42612fae46c0809514f9e0e3a11ee1773287147cdeaeedff50709aa716341fe65240f4ad6777d6bfaf9726e5e52");
	}

	@Test
	public void blake2s() {
		testHash("BLAKE2s", "", "0x69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
		testHash("BLAKE2s", "abc", "0x508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
		testHash("BLAKE2s", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "0x6f4df5116a6f332edab1d9e10ee87df6557beab6259d7663f3bcd5722c13f189");
		testHash("BLAKE2s", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "0x358dd2ed0780d4054e76cb6f3a5bce2841e8e2f547431d4d09db21b66d941fc7");
	}

	@Test
	public void sha256() {
		testHash("SHA256", "", "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		testHash("SHA256", "abc", "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
		testHash("SHA256", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "0x248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
	}

	@Test
	public void sha512() {
		testHash("SHA512", "", "0xcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
		testHash("SHA512", "abc", "0xddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
		testHash("SHA512", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "0x8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
	}
}
