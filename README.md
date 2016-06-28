
Noise-Java Library
==================

Noise-Java is a plain Java implementation of the
[Noise Protocol](http://noiseprotocol.org), intended as a
reference implementation.  The code is distributed under the
terms of the MIT license.

This library is written in plain Java, making use of the Java Cryptography
Extension (JCE) to provide cryptographic primitives and infrastructure.
Where a primitive is not normally present in standard JDK's, Noise-Java
provides fallback implementations.  It is assumed that the platform JDK
has the following providers built-in:

 * SHA-256
 * SHA-512
 * AES/GCM/NoPadding

If AES/GCM/NoPadding is not available, then the Noise-Java library will
emulate GCM on top of AES/CTR/NoPadding using a custom GHASH implementation.
If CTR mode isn't available either, then the "AESGCM" cipher cannot be used.

All other cryptographic primitives are emulated with plain Java
reference implementations: ChaChaPoly, BLAKE2s, BLAKE2b, Curve25519,
and Curve448.

If you have better implementations of the cryptographic primitives
available, you can modify the createDH(), createCipher(), and
createHash() functions in the "Noise" class to integrate your versions.

The [documentation](http://rweather.github.com/noise-java/index.html)
contains more information on the library, examples, and how to build it.

For more information on this library, to report bugs, to contribute,
or to suggest improvements, please contact the author Rhys Weatherley via
[email](mailto:rhys.weatherley@gmail.com).
