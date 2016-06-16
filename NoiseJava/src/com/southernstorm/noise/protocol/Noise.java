package com.southernstorm.noise.protocol;

/**
 * Constants for the Noise protocol library.
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

}
