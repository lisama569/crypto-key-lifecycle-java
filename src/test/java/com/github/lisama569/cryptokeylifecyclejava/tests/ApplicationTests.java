package com.github.lisama569.cryptokeylifecyclejava.tests;

import org.springframework.test.annotation.DirtiesContext;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * @author Vincent
 * @version 1.0
 */
@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class ApplicationTests {
    @Test
    public void contentLoad() {
    }
}
