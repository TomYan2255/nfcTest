/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.coolbitx.nfc.utils;

//import coolwallets.se.test.Util.keccak.Keccak256;
//import coolwallets.se.test.Util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.spongycastle.util.encoders.Hex;
import static com.coolbitx.nfc.utils.HexUtil.*;
import static junit.framework.Assert.assertTrue;

/**
 *
 * @author liu
 */
public class HashUtil {

    public static String RIPEMD160(String data) {
        RIPEMD160Digest ripemd160Digest = new RIPEMD160Digest();
        byte[] input = HexUtil.toByteArray(data);
        ripemd160Digest.update(input, 0, input.length);
        byte[] hashedPublicKey = new byte[20];
        ripemd160Digest.doFinal(hashedPublicKey, 0);
        return HexUtil.toHexString(hashedPublicKey,20);
    }

    public static String hash160(String data) {
        return RIPEMD160(SHA256(data));
    }

    public static String SHA1(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.update(Hex.decode(data));
            byte messageDigest[] = digest.digest();

            return HexUtil.toHexString(messageDigest,20);
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getClass().getSimpleName() + e.toString());
        }
        assertTrue("SHA Error",false);
        return null;
    }

    public static String SHA256(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(Hex.decode(data));
            byte[] messageDigest = digest.digest();

            return HexUtil.toHexString(messageDigest,32);
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getClass().getSimpleName() + e.toString());
        }
        assertTrue("SHA Error",false);
        return null;
    }

    public static String doubleSHA256(String data) {
        return SHA256(SHA256(data));
    }

    public static String SHA512(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            digest.update(Hex.decode(data));
            byte messageDigest[] = digest.digest();

            return HexUtil.toHexString(messageDigest,64);
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getClass().getSimpleName() + e.toString());
        }
        assertTrue("SHA Error",false);
        return null;
    }

    public static String SHA3256(String data) {
        SHA3.DigestSHA3 digestSHA3 = new SHA3.Digest256();
        byte[] digest = digestSHA3.digest(hexStringToByteArray(data));
        return HexUtil.toHexString(digest,32);
    }

    public static String SHA3512(String data) {
        SHA3.DigestSHA3 digestSHA3 = new SHA3.Digest512();
        byte[] digest = digestSHA3.digest(hexStringToByteArray(data));
        return HexUtil.toHexString(digest,64);
    }

    public static String Keccak256(String data) {
        Keccak.DigestKeccak kecc = new Keccak.Digest256();
        kecc.update(hexStringToByteArray(data));
        return HexUtil.toHexString(kecc.digest(),32);
    }

    public static String Keccak512(String data) {
        Keccak.DigestKeccak kecc = new Keccak.Digest512();
        kecc.update(hexStringToByteArray(data));
        return HexUtil.toHexString(kecc.digest(),64);
    }


    public static String HMAC2512(String key,String data){
        try{
        byte[] ret=new byte[64];
        HMAC(Hex.decode(key),0,key.length()/2,Hex.decode(data),0,data.length()/2,ret,0,MessageDigest.getInstance("SHA-512"));
        return HexUtil.toHexString(ret,64);
        }catch(Exception e){
            assertTrue("HMAC2512",false);
            return "error";
        }
    }
    
    private static int HMAC(byte[] key, int keyOff, int keyLength,
                byte[] buf, int offset, int length, byte[] destbuf,
                int destOffset, MessageDigest hash) {
        try{
	final byte IPAD = (byte) 0x36;
	final byte OPAD = (byte) 0x5c;

        short blockSize = 128;
        //if (hash == ShaUtil.sha_1) {
        //        blockSize = 64;
        //}
        byte[] workspace = new byte[blockSize + hash.getDigestLength()];

        if (keyLength > blockSize) {
                hash.update(key, keyOff, keyLength);
                hash.digest(workspace, 0,blockSize);
        } else {
                System.arraycopy(key, keyOff, workspace, 0,
                                keyLength);
        }

        // Setup IPAD secrets
        for (short ctr = (short) 0; ctr < blockSize; ctr++) {
                workspace[ctr] ^= IPAD;
        }

        // hash(i_key_pad | message)
        hash.update(workspace, 0, blockSize);
        hash.update(buf, offset, length);
        hash.digest(workspace,
                        blockSize,hash.getDigestLength());

        // transform workspace[(short)(0~blockSize)] from IPAD to OPAD
        for (short ctr = (short) 0; ctr < blockSize; ctr++) {
                workspace[ ctr] ^= IPAD;
                workspace[ ctr] ^= OPAD;
        }

        hash.update(workspace, 0,blockSize + hash.getDigestLength());
        hash.digest(destbuf, destOffset,hash.getDigestLength());

        return hash.getDigestLength();
        }catch(Exception e){
            assertTrue("HMAC",false);
            return 0;
        }
    }
}
