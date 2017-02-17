/*
 * Copyright (C) 2013 Southern Storm Software, Pty Ltd.
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

package com.southernstorm.json;

import java.io.IOException;
import java.io.Reader;

/**
 * Recursive-descent parser for JSON streams.
 * 
 * Intentionally compatible with android.util.JsonReader.
 */
public class JsonReader {

	private Reader in;
	private JsonToken token;
	private boolean lenient;
	private boolean booleanValue;
	private String stringValue;
	private int ungetCh;

	public JsonReader(Reader in) {
		this.in = in;
		this.token = JsonToken.READ_FIRST;
		this.lenient = false;
		this.ungetCh = -2;
	}

	public void beginArray() throws IOException {
		expectNext(JsonToken.BEGIN_ARRAY, "JSON begin array expected");
	}

	public void beginObject() throws IOException {
		expectNext(JsonToken.BEGIN_OBJECT, "JSON begin object expected");
	}

	public void close() throws IOException {
		in.close();
	}

	public void endArray() throws IOException {
		expectNext(JsonToken.END_ARRAY, "JSON end array expected");
	}

	public void endObject() throws IOException {
		expectNext(JsonToken.END_OBJECT, "JSON end array expected");
	}

	public boolean hasNext() throws IOException {
		if (this.token == JsonToken.READ_FIRST)
			nextToken();
		while (this.token == JsonToken.COMMA)
			nextToken(); // Very lenient - multiple separating commas allowed.
		return this.token != JsonToken.END_ARRAY
				&& this.token != JsonToken.END_OBJECT;
	}

	public boolean isLenient() {
		return this.lenient;
	}

	public void setLenient(boolean lenient) {
		// Lenient mode as described in the Android documentation is not implemented.
		this.lenient = lenient;
	}

	public boolean nextBoolean() throws IOException, IllegalStateException {
		if (this.token == JsonToken.READ_FIRST)
			nextToken();
		if (this.token != JsonToken.BOOLEAN)
			throw new IllegalStateException("JSON boolean value expected");
		boolean value = booleanValue;
		nextToken();
		return value;
	}

	public double nextDouble() throws IOException, IllegalStateException, NumberFormatException {
		if (this.token == JsonToken.READ_FIRST)
			nextToken();
		double value;
		if (this.token == JsonToken.STRING || token == JsonToken.NUMBER) {
			value = Double.parseDouble(stringValue);
		} else {
			throw new IllegalStateException("JSON double value expected");
		}
		nextToken();
		return value;
	}

	public int nextInt() throws IOException, IllegalStateException, NumberFormatException {
		if (this.token == JsonToken.READ_FIRST)
			nextToken();
		int value;
		if (this.token == JsonToken.STRING || this.token == JsonToken.NUMBER) {
			value = Integer.parseInt(stringValue);
		} else {
			throw new IllegalStateException("JSON int value expected");
		}
		nextToken();
		return value;
	}

	public long nextLong() throws IOException, IllegalStateException, NumberFormatException {
		if (this.token == JsonToken.READ_FIRST)
			nextToken();
		long value;
		if (this.token == JsonToken.STRING || this.token == JsonToken.NUMBER) {
			value = Long.parseLong(stringValue);
		} else {
			throw new MalformedJsonException("JSON long value expected");
		}
		nextToken();
		return value;
	}

	public String nextName() throws IOException, IllegalStateException {
		if (this.token == JsonToken.READ_FIRST)
			nextToken();
		if (this.token != JsonToken.NAME)
			throw new IllegalStateException("JSON property name expected");
		String value = stringValue;
		nextToken();
		return value;
	}

	public void nextNull() throws IOException, IllegalStateException {
		if (this.token == JsonToken.READ_FIRST)
			nextToken();
		if (this.token != JsonToken.NULL)
			throw new IllegalStateException("JSON null value expected");
		nextToken();
	}

	public String nextString() throws IOException, IllegalStateException {
		if (this.token == JsonToken.READ_FIRST)
			nextToken();
		String value;
		if (this.token == JsonToken.STRING || this.token == JsonToken.NUMBER)
			value = stringValue;
		else if (this.token == JsonToken.BOOLEAN)
			value = Boolean.toString(booleanValue);
		else if (this.token == JsonToken.NULL)
			value = null;
		else
			throw new IllegalStateException("JSON string value expected");
		nextToken();
		return value;
	}

	public JsonToken peek() throws IOException {
		if (this.token == JsonToken.READ_FIRST)
			nextToken();
		return this.token;
	}

	public void skipValue() throws IOException {
		switch (peek()) {
		case BEGIN_ARRAY:
			beginArray();
			while (hasNext())
				skipValue();
			endArray();
			break;
		case BEGIN_OBJECT:
			beginObject();
			while (hasNext()) {
				nextName();
				skipValue();
			}
			endObject();
			break;
		case END_DOCUMENT:
			break;
		default:
			nextToken();
			break;
		}
	}

	private void parseNumber(int ch) throws IOException {
		StringBuilder builder = new StringBuilder();
		builder.append((char)ch);
		ch = in.read();
		while ((ch >= '0' && ch <= '9') || ch == '-' || ch == '+' || ch == 'e' || ch == 'E' || ch == '.') {
			builder.append((char)ch);
			ch = in.read();
		}
		ungetCh = ch;
		stringValue = builder.toString();
	}

	private void parseString() throws IOException {
		StringBuilder builder = new StringBuilder();
		int ch = in.read();
		outer: while (ch != '"') {
			if (ch == -1) {
				ungetCh = ch;
				break;
			} else if (ch == '\\') {
				ch = in.read();
				if (ch == 'b')
					builder.append('\u0008');
				else if (ch == 'f')
					builder.append('\u000C');
				else if (ch == 'n')
					builder.append('\n');
				else if (ch == 'r')
					builder.append('\r');
				else if (ch == 't')
					builder.append('\t');
				else if (ch != 'u')
					builder.append((char)ch);
				else if (ch == -1) {
					ungetCh = ch;
					break;
				} else {
					int value = 0;
					int digits = 0;
					while (digits < 4) {
						ch = in.read();
						if (ch >= '0' && ch <= '9')
							value = value * 16 + (ch - '0');
						else if (ch >= 'A' && ch <= 'F')
							value = value * 16 + (ch - 'A' + 10);
						else if (ch >= 'a' && ch <= 'f')
							value = value * 16 + (ch - 'a' + 10);
						else {
							builder.append((char)value);
							continue outer;
						}
						++digits;
					}
					builder.append((char)value);
				}
			} else {
				builder.append((char)ch);
			}
			ch = in.read();
		}
		stringValue = builder.toString();
	}

	private boolean checkForColon() throws IOException {
		int ch = ungetCh;
		if (ch == -2)
			ch = in.read();
		while (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
			ch = in.read();
		if (ch == ':') {
			ungetCh = -2;
			return true;
		} else {
			ungetCh = ch;
			return false;
		}
	}

	private void checkNamedToken(String name) throws IOException {
		int index = 1;
		int ch = in.read();
		for (; index < name.length(); ++index) {
			if (ch != name.charAt(index))
				break;
			ch = in.read();
		}
		if (index < name.length() || (ch >= 'a' && ch <= 'z')
				|| (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
				|| ch == '_') {
			throw new MalformedJsonException("Invalid keyword, expected: '"
					+ name + "'");
		}
		ungetCh = ch;
	}

	private void nextToken() throws IOException {
		int ch = ungetCh;
		if (ch == -2)
			ch = in.read();
		while (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
			ch = in.read();
		ungetCh = -2;
		switch (ch) {
		case -1:
			token = JsonToken.END_DOCUMENT;
			ungetCh = -1;
			break;
		case '{':
			token = JsonToken.BEGIN_OBJECT;
			break;
		case '}':
			token = JsonToken.END_OBJECT;
			break;
		case '[':
			token = JsonToken.BEGIN_ARRAY;
			break;
		case ']':
			token = JsonToken.END_ARRAY;
			break;
		case ',':
			token = JsonToken.COMMA;
			break;
		case '-':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			parseNumber(ch);
			token = JsonToken.NUMBER;
			break;
		case '"':
			parseString();
			if (checkForColon())
				token = JsonToken.NAME;
			else
				token = JsonToken.STRING;
			break;
		case 'n':
			checkNamedToken("null");
			token = JsonToken.NULL;
			break;
		case 't':
			checkNamedToken("true");
			token = JsonToken.BOOLEAN;
			booleanValue = true;
			break;
		case 'f':
			checkNamedToken("false");
			token = JsonToken.BOOLEAN;
			booleanValue = false;
			break;
		default:
			throw new MalformedJsonException(
					"Invalid character in JSON stream: '" + (char) ch + "'");
		}
	}

	private void expectNext(JsonToken token, String message) throws IOException {
		if (this.token == JsonToken.READ_FIRST)
			nextToken();
		if (this.token != token)
			throw new MalformedJsonException(message);
		nextToken();
	}
}
