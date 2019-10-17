/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.coolbitx.nfc.utils;

//import coolwallets.se.test.Util.rlp.RlpEncoder;
//import coolwallets.se.test.Util.keccak.*;
//import coolwallets.se.test.Util.*;

import java.util.Random;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import static com.coolbitx.nfc.utils.HexUtil.*;

import static junit.framework.Assert.assertTrue;

/**
 *
 * @author liu
 */
public class CommonUtil {

    public static String sign(String cmd, String data, String nonce, String privateKey) {
        //HashUtil.SHA256(cmd + data + nonce);

        byte[] byteSHA = Sha256Hash.hash(HexUtil.toByteArray(cmd + data + nonce));
        Sha256Hash hash = Sha256Hash.wrap(byteSHA);
        byte[] priKeyByte;
        if (null == privateKey) {
            priKeyByte = hexStringToByteArray("b8c4cb218f0e4d31ae51bcea2081de7dba14be711197a4efb7c73c2721c82826");
        } else {
            priKeyByte = hexStringToByteArray(privateKey);
        }

        ECKey ecKey = ECKey.fromPrivate(priKeyByte);
        ECKey.ECDSASignature sig = ecKey.sign(hash);
        byte[] res = sig.encodeToDER();

        return bytesToHex(res);
    }

//    public static boolean verify(byte[] data, byte[] signature, String pubKey) {
//        boolean result = ECKey.verify(data, signature, hexStringToByteArray(pubKey));
//        return result;
//    }
//
//    public static boolean verify(String data, String signature, String pubKey) {
//        boolean result = ECKey.verify(HexUtil.toByteArray(data), HexUtil.toByteArray(signature), HexUtil.toByteArray(pubKey));
//        return result;
//    }

    public static void assertLength(String message,String data,int byteLength){
        assertTrue(message,data.length()==byteLength*2);
    }
    




    public static String decRandom(int length) {
        Random rand = new Random();
        String ret="";
        for(int i=0;i<length;i++){
            ret+=rand.nextInt(10);
        }
        return ret;
    }
    public static String hexRandom(int byteLength) {
        Random ran = new Random();
        byte[] temp = new byte[byteLength];
        ran.nextBytes(temp);

        return HexUtil.toHexString(temp,byteLength);
    }


}
