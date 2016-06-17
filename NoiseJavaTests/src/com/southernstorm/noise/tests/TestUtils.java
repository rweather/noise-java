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

import java.io.UnsupportedEncodingException;

import javax.xml.bind.DatatypeConverter;

public class TestUtils {

	/**
	 * Convert a string into a binary byte array.
	 * 
	 * @param data The string data to convert.
	 * @return The binary version of the data.
	 * 
	 * If the string starts with "0x", then the remainder of the string is
	 * interpreted as hexadecimal.  Otherwise the string is interpreted
	 * as a literal string (e.g. "abc") and converted with the UTF-8 encoding.
	 */
	public static byte[] stringToData(String data)
	{
		if (data.startsWith("0x")) {
			return DatatypeConverter.parseHexBinary(data.substring(2));
		} else {
			try {
				return data.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				return new byte [0];
			}
		}
	}

}
