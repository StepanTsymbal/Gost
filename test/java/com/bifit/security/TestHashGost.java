package com.bifit.security;

import static org.junit.Assert.assertEquals;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

public class TestHashGost {

    @Test
    public void testHash() {

        String s = "";
        String res = "CE85B99CC46752FFFEE35CAB9A7B0278ABB4C2D2055CFF685AF4912C49490F8D";

        // Hasher hash = new Hasher();

        assertEquals(res, DatatypeConverter.printHexBinary(Hasher.hash(s)));
    }

    @Test
    public void testGostEnc() {

        String key = "8CA6002BF5EB5D09C05F356D8FF37F66629AA3741D670AAA6291732706AA6530";
        String s = "FE4A389A2FDAA706393CFB694ABD3653A703AD16164845C973F53F8F9D1D9D06";
        String res = "3602786EFA459AF5A8F03F1F6D38582E56C2974A7AB5B3EFE4A51EEEB84677DC";

        byte[] bytesForEnc = DatatypeConverter.parseHexBinary(s);
        byte[] byteKey = DatatypeConverter.parseHexBinary(key);

        Cipher encryptor = new Cipher();

        assertEquals(res, DatatypeConverter.printHexBinary(encryptor.encrypt(bytesForEnc, byteKey)));
    }

    @Test
    public void testGostDec() {

        String key = "8CA6002BF5EB5D09C05F356D8FF37F66629AA3741D670AAA6291732706AA6530";
        String s = "3602786EFA459AF5A8F03F1F6D38582E56C2974A7AB5B3EFE4A51EEEB84677DC";
        String res = "FE4A389A2FDAA706393CFB694ABD3653A703AD16164845C973F53F8F9D1D9D06";

        byte[] bytesForDec = DatatypeConverter.parseHexBinary(s);
        byte[] byteKey = DatatypeConverter.parseHexBinary(key);

        Cipher encryptor = new Cipher();

        assertEquals(res, DatatypeConverter.printHexBinary(encryptor.decrypt(bytesForDec, byteKey)));
    }
}
