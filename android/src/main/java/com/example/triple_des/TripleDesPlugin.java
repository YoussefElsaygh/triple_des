package com.example.triple_des;

import androidx.annotation.NonNull;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.PluginRegistry.Registrar;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * TripleDesPlugin
 */
public class TripleDesPlugin implements FlutterPlugin, MethodCallHandler {
    /// The MethodChannel that will the communication between Flutter and native Android
    ///
    /// This local reference serves to register the plugin with the Flutter Engine and unregister it
    /// when the Flutter Engine is detached from the Activity
    private MethodChannel channel;

    @Override
    public void onAttachedToEngine(@NonNull FlutterPluginBinding flutterPluginBinding) {
        channel = new MethodChannel(flutterPluginBinding.getBinaryMessenger(), "triple_des");
        channel.setMethodCallHandler(this);
    }

    @Override
    public void onMethodCall(@NonNull MethodCall call, @NonNull Result result) {
        if (call.method.equals("decrypt3Des")) {
            String message = call.arguments["message"];
            String key = call.arguments["key"];
            final DesedeCrypter crypter = new DesedeCrypter();

            String res = crypter.decrypt(message, key);
            result.success(res);
            return;
        }
        if (call.method.equals("encrypt3Des")) {
            String message = call.arguments("message");
            String key = call.arguments("key");
            final DesedeCrypter crypter = new DesedeCrypter();

            String res = crypter.encrypt(message, key);
            result.success(res);
            return;
        }
    }

    @Override
    public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
        channel.setMethodCallHandler(null);
    }
}

class DesedeCrypter {

    private static final String CRYPT_ALGORITHM = "DESede";
    private static final String PADDING = "DESede/ECB/PKCS5Padding";
    private static final String CHAR_ENCODING = "UTF-8";

    /**
     * Encrypt text to encrypted-text
     *
     * @param text
     * @return
     */
    public String encrypt(String text, String key) {

        if (text == null) {
            return null;
        }

        String retVal = null;

        try {

            final SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), CRYPT_ALGORITHM);


            final Cipher cipher = Cipher.getInstance(PADDING);

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

            final byte[] encrypted = cipher.doFinal(text.getBytes(CHAR_ENCODING));

            retVal = new String(encodeHex(encrypted));

        } catch (Exception e) {
            e.printStackTrace();
        }

        return retVal;
    }

    /**
     * Decrypt encrypted-text
     *
     * @param text
     * @return
     */
    public String decrypt(String text, String key) {

        if (text == null) {
            return null;
        }

        String retVal = null;

        try {

            final SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), CRYPT_ALGORITHM);

            final Cipher cipher = Cipher.getInstance(PADDING);

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

            final byte[] decrypted = cipher.doFinal(decodeHex(text.toCharArray()));

            retVal = new String(decrypted, CHAR_ENCODING);

        } catch (Exception e) {

            e.printStackTrace();
        }

        return retVal;
    }

    /**
     * Converts an array of characters representing hexadecimal values into an array
     * of bytes of those same values. The returned array will be half the length of
     * the passed array, as it takes two characters to represent any given byte. An
     * exception is thrown if the passed char array has an odd number of elements.
     * <br>
     * Portion of Apache Software Foundation
     *
     * @param data An array of characters containing hexadecimal digits
     * @return A byte array containing binary data decoded from the supplied char
     * array.
     * @throws Exception Thrown if an odd number or illegal of characters is supplied
     */
    private byte[] decodeHex(char[] data) throws Exception {

        int len = data.length;

        if ((len & 0x01) != 0) {
            throw new Exception("Odd number of characters.");
        }

        byte[] out = new byte[len >> 1];

        // two characters form the hex value.
        for (int i = 0, j = 0; j < len; i++) {

            int f = toDigit(data[j], j) << 4;
            j++;
            f = f | toDigit(data[j], j);
            j++;
            out[i] = (byte) (f & 0xFF);
        }

        return out;
    }

    /**
     * Converts a hexadecimal character to an integer. <br>
     * Portion of Apache Software Foundation
     *
     * @param ch    A character to convert to an integer digit
     * @param index The index of the character in the source
     * @return An integer
     * @throws Exception Thrown if ch is an illegal hex character
     */
    private int toDigit(char ch, int index) throws Exception {
        int digit = Character.digit(ch, 16);
        if (digit == -1) {
            throw new Exception("Illegal hexadecimal character " + ch + " at index " + index);
        }
        return digit;
    }

    /**
     * Converts an array of bytes into an array of characters representing the
     * hexadecimal values of each byte in order. The returned array will be double
     * the length of the passed array, as it takes two characters to represent any
     * given byte. <br>
     * Portion of Apache Software Foundation
     *
     * @param data     a byte[] to convert to Hex characters
     * @param toDigits the output alphabet
     * @return A char[] containing hexadecimal characters
     */
    private char[] encodeHex(byte[] data) {

        final char[] DIGITS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        int l = data.length;
        char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = DIGITS[(0xF0 & data[i]) >>> 4];
            out[j++] = DIGITS[0x0F & data[i]];
        }
        return out;
    }
}
