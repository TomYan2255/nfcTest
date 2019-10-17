/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.coolbitx.nfc.utils;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
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
import org.bitcoinj.core.ECKey;
import org.spongycastle.util.encoders.Hex;

import static com.coolbitx.nfc.utils.HexUtil.*;
import static junit.framework.Assert.assertTrue;

/**
 *
 * @author liu
 */
public class CryptoUtil {


    public static String encryptAES(String key,String plain){
        try{
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = ByteBuffer.allocate(16).putInt(0).array();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        SecretKeySpec encryptSpec = new SecretKeySpec(Hex.decode(key), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, encryptSpec, ivSpec);
        String ciphertext = Hex.toHexString(cipher.doFinal(Hex.decode(plain)));
        return ciphertext;
        }catch(Exception e){
            assertTrue("encryptAES",false);
            return "Error!";
        }
    }

    public static String decryptAES(String key,String plain){
        try{
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = ByteBuffer.allocate(16).putInt(0).array();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        SecretKeySpec decryptSpec = new SecretKeySpec(Hex.decode(key), "AES");
        cipher.init(Cipher.DECRYPT_MODE, decryptSpec, ivSpec);
        String ciphertext = Hex.toHexString(cipher.doFinal(Hex.decode(plain)));
        return ciphertext;
        }catch(Exception e){
            assertTrue("decryptAES",false);
            return "Error!";
        }
    }


    public static String eciesDecrypt(String input, String priKey) {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256k1"));

            ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

            KeyFactory kf = KeyFactory.getInstance("EC");

            //Decrypt
            String ephemX = input.substring(2, 66);
            String ephemY = input.substring(66, 130);
            String macResult = input.substring(130, 130 + 40).toUpperCase();
            String ciphertext = input.substring(130 + 40, input.length());

            //Initialize our private key:
            BigInteger big = new BigInteger(priKey, 16);
            ECPrivateKeySpec ecPri = new ECPrivateKeySpec(big, ecParameterSpec);

            // Read other's public key:
            ECPoint ecPoint = new ECPoint(
                    new BigInteger(ephemX, 16),
                    new BigInteger(ephemY, 16));
            ECPublicKeySpec ecPub = new ECPublicKeySpec(ecPoint, ecParameterSpec);
            // Perform key agreement
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kf.generatePrivate(ecPri));
            ka.doPhase(kf.generatePublic(ecPub), true);

            // Read shared secret
            byte[] sharedSecret = ka.generateSecret();

            // Derive a key from the shared secret
            MessageDigest hash = MessageDigest.getInstance("SHA-512");
            hash.update(sharedSecret);
            byte[] derivedKey = hash.digest();
            byte[] decryptKey = new byte[derivedKey.length / 2];
            byte[] macKey = new byte[derivedKey.length / 2];
            System.arraycopy(derivedKey, 0, decryptKey, 0, decryptKey.length);
            System.arraycopy(derivedKey, decryptKey.length, macKey, 0, macKey.length);

            SecretKey secretKey = new SecretKeySpec(macKey, "HmacSHA1");
            Mac mac = Mac.getInstance(secretKey.getAlgorithm());
            mac.init(secretKey);
            byte[] iv = ByteBuffer.allocate(16).putInt(0).array();
            mac.update(iv);
            StringBuilder ephemPublicKey = new StringBuilder("04");
            ephemPublicKey.append(ephemX);
            ephemPublicKey.append(ephemY);
            mac.update(Hex.decode(ephemPublicKey.toString()));
            mac.update(Hex.decode(ciphertext));
            String bigMac = Hex.toHexString(mac.doFinal()).toUpperCase();
            if (macResult.equals(bigMac)) {
                System.out.println("Mac valid");
            } else {
                System.out.println("Mac invalid");
            }
            byte[] plaintext = decrypt(decryptKey, ciphertext);
            return Hex.toHexString(plaintext);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException | InvalidKeySpecException | InvalidKeyException e) {
            System.out.println(e.getClass().getSimpleName() + e.toString());
        }
        return null;
    }

    public static byte[] decrypt(byte[] decryptKey, String ciphertext) {
        byte[] iv = ByteBuffer.allocate(16).putInt(0).array();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec decryptSpec = new SecretKeySpec(decryptKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, decryptSpec, ivSpec);

            byte[] plaintext = cipher.doFinal(Hex.decode(ciphertext));
            return plaintext;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(HashUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static String eciesEncrypt(String plain, ECKey eckey) {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256k1"));

            ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

            //Initialize our private key:
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(ecParameterSpec, new SecureRandom());
            KeyPair keypair = keyGen.generateKeyPair();

            // random number x elliptic curve G
            ECPublicKey ecpubkey = (ECPublicKey) keypair.getPublic();
            String pubkey = KeyUtil.getPublicKey(ecpubkey);

            // Read other's public key:
            if (eckey == null) {
                eckey = ECKey.fromPublicOnly(hexStringToByteArray("023d268ced2427d805fddca0747f0c5c40863b7a5bbddf2d76cfa033ba020c8d7b"));
            }

            ECPoint ecPoint = KeyUtil.getECPoint(KeyUtil.getPublicKey(eckey));
            ECPublicKeySpec ecPub = new ECPublicKeySpec(ecPoint, ecParameterSpec);

            // Perform key agreement
            KeyFactory kf = KeyFactory.getInstance("EC");
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kf.generatePrivate(new PKCS8EncodedKeySpec(keypair.getPrivate().getEncoded())));
            ka.doPhase(kf.generatePublic(ecPub), true);

            // Read shared secret
            byte[] sharedSecret = ka.generateSecret();
//            System.out.printf("Shared secret: %s%n", printHexBinary(sharedSecret));

            // Derive a key from the shared secret
            MessageDigest hash = MessageDigest.getInstance("SHA-512");
            hash.update(sharedSecret);
            byte[] derivedKey = hash.digest();
//            System.out.printf("Final key: %s%n", printHexBinary(derivedKey));
            byte[] encryptKey = new byte[derivedKey.length / 2];
            byte[] macKey = new byte[derivedKey.length / 2];
            System.arraycopy(derivedKey, 0, encryptKey, 0, encryptKey.length);
            System.arraycopy(derivedKey, encryptKey.length, macKey, 0, macKey.length);

            //Encrypt
            byte[] plaintext = Hex.decode(plain);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = ByteBuffer.allocate(16).putInt(0).array();
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            SecretKeySpec encryptSpec = new SecretKeySpec(encryptKey, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, encryptSpec, ivSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);
//            System.out.println("ciphertext: " + Hex.toHexString(ciphertext));

            SecretKey secretKey = new SecretKeySpec(macKey, "HmacSHA1");
            Mac mac = Mac.getInstance(secretKey.getAlgorithm());
//            StringBuilder pubKey = new StringBuilder("04");
//            pubKey.append(eckey.getPubKeyPoint().getAffineXCoord().toString());
//            pubKey.append(eckey.getPubKeyPoint().getAffineYCoord().toString());
            mac.init(secretKey);
            mac.update(iv);
            mac.update(hexStringToByteArray(pubkey));
            mac.update(ciphertext);
            byte[] macResult = mac.doFinal();

            StringBuilder output = new StringBuilder();
            output.append(pubkey);
            output.append(bytesToHex(macResult));
            output.append(bytesToHex(ciphertext));

            return output.toString();
        } catch (NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidParameterSpecException ex) {
            Logger.getLogger(CryptoUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }


}
