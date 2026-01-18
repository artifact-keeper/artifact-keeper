package com.test;

/**
 * Test class for E2E native client testing.
 */
public class TestClass {

    /**
     * Returns a greeting message.
     * @return greeting string
     */
    public static String hello() {
        return "Hello from test-package!";
    }

    /**
     * Main entry point.
     * @param args command line arguments
     */
    public static void main(String[] args) {
        System.out.println(hello());
    }
}
