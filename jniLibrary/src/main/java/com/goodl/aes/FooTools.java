package com.goodl.aes;

public class FooTools {

    // Used to load the library on application startup.
    static {
        System.loadLibrary("fooLib");
    }

    /**
     * AES加密, CBC, PKCS5Padding
     */
    public static native String method01(String str);

    /**
     * AES解密, CBC, PKCS5Padding
     */
    public static native String method02(String str);

}
