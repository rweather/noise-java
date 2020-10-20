package com.southernstorm.noise.tests;

import java.io.InputStream;
import java.net.URL;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

public class UnitVectorTests {

  private static final String testVectorsCommit = "5d0a74760320e5486ced302e36ccad91606aac43";

  @Test
  void testBasicVector() throws Exception {
    try (InputStream stream = new URL(
        "https://raw.githubusercontent.com/rweather/noise-c/" + testVectorsCommit
            + "/tests/vector/noise-c-basic.txt").openStream()) {
      VectorTests vectorTests = new VectorTests();
      vectorTests.processInputStream(stream);
      Assert.assertEquals(vectorTests.getFailed(), 0);
    }
  }
}
