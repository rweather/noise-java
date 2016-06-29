
Noise-Java Library
==================

Noise-Java is a plain Java implementation of the
[Noise Protocol](http://noiseprotocol.org), intended as a
reference implementation.  The code is distributed under the
terms of the MIT license.

This library is written in plain Java, making use of the Java Cryptography
Extension (JCE) to provide cryptographic primitives and infrastructure.
When a primitive is not supported by the platform's JDK, Noise-Java provides
a fallback implementation in plain Java.

The following algorithms are commonly available in standard JDK's and
Noise-Java will try to use them if present:

 * SHA-256
 * SHA-512
 * AES/CTR/NoPadding

Some JDK installations restrict the use of 256-bit AES keys.  You may need to
install the "Unlimited Strength Policy Files" for your JDK to get around this
restriction.  Alternatively, the plain Java fallback implementation of AESGCM
in Noise-Java does not have any such restrictions.

If you have better implementations of the cryptographic primitives
available, you can modify the createDH(), createCipher(), and
createHash() functions in the "Noise" class to integrate your versions.

The [package documentation](http://rweather.github.com/noise-java/index.html)
contains more information on the classes in the Noise-Java library.

For more information on this library, to report bugs, to contribute,
or to suggest improvements, please contact the author Rhys Weatherley via
[email](mailto:rhys.weatherley@gmail.com).
