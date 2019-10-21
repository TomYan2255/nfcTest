/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.coolbitx.nfc.utils;

import android.util.Log;

import com.coolbitx.nfc.utils.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.Security;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
//import static javax.xml.bind.DatatypeConverter.parseHexBinary;
//import static javax.xml.bind.DatatypeConverter.printHexBinary;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.spongycastle.util.encoders.Hex;


/**
 *
 * @author liu
 */
public class KeyUtil {


    public static ECKey genECKey() {
        return new ECKey();
    }
    public static String genPublicKey() {
        return getPublicKey(genECKey());
    }

    public static ECKey getECKey(String key) {

        return ECKey.fromPrivate(HexUtil.toByteArray(key));
    }

    public static ECPoint getECPoint(String publicKey) {
        return new ECPoint(
            new BigInteger(publicKey.substring(2,66), 16),
            new BigInteger(publicKey.substring(66,130), 16));
    }



    public static String getPublicKey(String key) {
        return getPublicKey(getECKey(key));
    }

    public static String getPublicKey(ECKey eckey) {

        if (null == eckey) {
            eckey = new ECKey();
        }
        return getPublicKey(eckey.getPubKeyPoint());
    }

    public static String getPublicKey(ECPublicKey ecpubkey) {
        return getPublicKey(ecpubkey.getW());
    }

    public static String getPublicKey(org.bouncycastle.math.ec.ECPoint ecPoint) {
        return "04"+HexUtil.toHexString(ecPoint.getAffineXCoord().toBigInteger(),32)+HexUtil.toHexString(ecPoint.getAffineYCoord().toBigInteger(),32);
    }

    public static String getPublicKey(org.spongycastle.math.ec.ECPoint ecPoint) {
        return "04"+HexUtil.toHexString(ecPoint.getAffineXCoord().toBigInteger(),32)+HexUtil.toHexString(ecPoint.getAffineYCoord().toBigInteger(),32);
    }

    public static String getPublicKey(ECPoint ecPoint) {
        return "04"+HexUtil.toHexString(ecPoint.getAffineX(),32)+HexUtil.toHexString(ecPoint.getAffineY(),32);
    }

    public static String getEcdhKey(String pubKey,String priKey){
        try{

            Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
            //Security.addProvider(new BouncyCastleProvider());
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256k1"));
            ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

            ECPrivateKeySpec ecPri = new ECPrivateKeySpec(new BigInteger(priKey,16), ecParameterSpec);
            ECPublicKeySpec ecPub = new ECPublicKeySpec(getECPoint(pubKey), ecParameterSpec);

            KeyFactory kf = KeyFactory.getInstance("EC");
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kf.generatePrivate(ecPri));
            ka.doPhase(kf.generatePublic(ecPub), true);
            return HexUtil.toHexString(ka.generateSecret(),32);

        }catch(Exception e){
           // assertTrue("getEcdhKey",false);
            return "Error!" +e.toString();
        }
    }

    public static String getCompressedPublicKey(String publicKey) {
        String prefix="04";
        int c=publicKey.charAt(129);
        if(c=='1'||c=='3'||c=='5'||c=='7'||c=='9'||c=='B'||c=='D'||c=='F'||c=='b'||c=='d'||c=='f'){
            prefix="03";
        }
        else if(c=='0'||c=='2'||c=='4'||c=='6'||c=='8'||c=='A'||c=='C'||c=='E'||c=='a'||c=='c'||c=='e'){
            prefix="02";
        }else{
           // assertTrue("getCompressedPublicKey",false);
        }
        return prefix + publicKey.substring(2,66);
    }

    public static String getChildChainCode(String parentPublicKey,String chainCode,String index){
        String addend=HashUtil.HMAC2512(chainCode, getCompressedPublicKey(parentPublicKey) + index);
        System.out.println("HMAC: " + addend);
        CommonUtil.assertLength("HMAC",addend,64);
        return addend.substring(64,128);
    }

    public static String getChildPublicKey(String parentPublicKey,String chainCode,String index){
        org.bouncycastle.asn1.x9.X9ECParameters params = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("secp256k1");
        org.bouncycastle.math.ec.ECCurve curve = params.getCurve();

        String addend=HashUtil.HMAC2512(chainCode,  getCompressedPublicKey(parentPublicKey) + index);
        System.out.println("HMAC: " + addend);
        CommonUtil.assertLength("HMAC",addend,64);
        String addendPublicKey = getPublicKey(addend.substring(0,64));

        org.bouncycastle.math.ec.ECPoint P = curve.createPoint(new BigInteger(parentPublicKey.substring(2,66),16), new BigInteger(parentPublicKey.substring(66,130),16));
        org.bouncycastle.math.ec.ECPoint Q = curve.createPoint(new BigInteger(addendPublicKey.substring(2,66),16), new BigInteger(addendPublicKey.substring(66,130),16));
        org.bouncycastle.math.ec.ECPoint R = P.add(Q).normalize();
        return getPublicKey(R);
    }

    public static String getChildPrivateKey(String parentPrivateKey,String chainCode,String index){
        String parentPublicKey = getPublicKey(parentPrivateKey);
        //String addend=HashUtil.HMAC2512(chainCode,"00"+parentPrivateKey+toHexString(index));
        String addend=HashUtil.HMAC2512(chainCode,  getCompressedPublicKey(parentPublicKey) + index);
        System.out.println("MAC:" + addend);
        CommonUtil.assertLength("HMAC",addend,64);
        return HexUtil.toHexString(new BigInteger(addend.substring(0,64),16)
            .add(new BigInteger(parentPrivateKey,16))
            .mod(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16))
            ,32);
    }
}
