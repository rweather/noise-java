package com.southernstorm.noise.tests;

import com.southernstorm.noise.protocol.HandshakeState;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.Assert.assertNotNull;

public class ProtocolTest {
    @Test
    public void testCreateHandshakeState() throws NoSuchAlgorithmException {
        HandshakeState client = new HandshakeState("Noise_NNpsk0_25519_ChaChaPoly_SHA256", HandshakeState.INITIATOR);
        assertNotNull(client);

        byte[] key = Base64.getDecoder().decode("LOaZwNhb6Ct5o5jRHIVQElRz4Lq25a4vEQ8TGTQT4hw=");
        assert key.length == 32;

        client.setPreSharedKeyForNNpsk(key, 0, key.length);
        byte[] prologue = "NoiseAPIInit\0\0".getBytes(StandardCharsets.US_ASCII);
        client.setPrologue(prologue, 0, prologue.length);
        client.start();

    }
}
