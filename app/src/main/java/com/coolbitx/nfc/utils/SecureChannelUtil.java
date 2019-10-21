package com.coolbitx.nfc.utils;

//import static junit.framework.Assert.assertTrue;
//import static junit.framework.Assert.fail;

public class SecureChannelUtil {

    protected static final String GenuineMasterChainCode_NonInstalled = "611c6956ca324d8656b50c39a0e5ef968ecd8997e22c28c11d56fb7d28313fa3";
    protected static final String GenuineMasterPublicKey_NonInstalled = "04e720c727290f3cde711a82bba2f102322ab88029b0ff5be5171ad2d0a1a26efcd3502aa473cea30db7bc237021d00fd8929123246a993dc9e76ca7ef7f456ade";
    protected static final String GenuineMasterChainCode_Test = "f5a0c5d9ffaee0230a98a1cc982117759c149a0c8af48635776135dae8f63ba4";
    protected static final String GenuineMasterPublicKey_Test = "0401e3a7de779276ef24b9d5617ba86ba46dc5a010be0ce7aaf65876402f6a53a5cf1fecab85703df92e9c43e12a49f33370761153216df8291b7aa2f1a775b086";
    protected static String salt = null;

    protected static String GenuineChildPublicKey = null;
    protected static String secureKey = null;

    public void establishSecureChannel() {
        System.out.println("========establishSecureChannel========");

        // generate a temp keyPair for this session, send the publicKey to SE
        // get the installType and cardName
        String sessionAppPrivateKey=CommonUtil.hexRandom(32);
        String ret = "";
                //send("80CE0000", KeyUtil.getPublicKey(sessionAppPrivateKey), -1);
        String installType = ret.substring(0,4);
        int cardNameLength = HexUtil.toInt(ret.substring(4,8));
        String cardNameHex = ret.substring(8,8+cardNameLength*2);
        ret = ret.substring(8+cardNameLength*2, ret.length());
        String nonceIndex = ret.substring(0,64);
        String testCipher = ret.substring(64, ret.length());
        // convert cardName from hexString to ASCII string (if needed)
        String cardName = HexUtil.getOriginalStringFromHexString(cardNameHex);
        System.out.println("CardNmHex:" + installType + " " + cardNameHex);
        System.out.println("CardNmStr:" + installType + " " + cardName);
        System.out.println("NonceIndx:" + installType + " " + nonceIndex);
        System.out.println("SesAppPri:" + sessionAppPrivateKey);
        System.out.println("SesAppPub:" + KeyUtil.getPublicKey(sessionAppPrivateKey));
        // cardName=="NON_INSTALLED" means that the card is not installed by CoolBitX, it may be fake or for development.
        // you can still use SecureChannel with nonInstalled card by ignoring this warning.
        // assertTrue("NonInstalled",!cardName.equals("NON_INSTALLED"));

        // get corresponding GenuieMasterPublicKey by installType
        String GenuineMasterPublicKey=null;
        String GenuineMasterChainCode=null;
        switch(installType){
            case "0000":
                GenuineMasterPublicKey = GenuineMasterPublicKey_NonInstalled;
                GenuineMasterChainCode = GenuineMasterChainCode_NonInstalled;
                break;
            case "0001":
                GenuineMasterPublicKey = GenuineMasterPublicKey_Test;
                GenuineMasterChainCode = GenuineMasterChainCode_Test;
                break;
            // add case "0002" here for real HSM key.
            default:
               // fail("Unregistered installType");
                break;
        }
        // derive the publicKey of SE from it's cardName and nonce
        String GenuineChild1PublicKey = KeyUtil.getChildPublicKey(GenuineMasterPublicKey,GenuineMasterChainCode,cardNameHex);
        String GenuineChild1ChainCode = KeyUtil.getChildChainCode(GenuineMasterPublicKey,GenuineMasterChainCode,cardNameHex);
        String GenuineChild2PublicKey = KeyUtil.getChildPublicKey(GenuineChild1PublicKey,GenuineChild1ChainCode,nonceIndex);
        System.out.println("GnuCh1Pub:" + GenuineChild1PublicKey);
        System.out.println("GnuCh1ChC:" + GenuineChild1ChainCode);
        System.out.println("GnuCh2Pub:" + GenuineChild2PublicKey);
        // do a ECDH keyAgreement, use the result key to encrypt following commands
        secureKey = KeyUtil.getEcdhKey(GenuineChild2PublicKey,sessionAppPrivateKey);
        System.out.println("secureKey:" + secureKey);
        // remember GenuineChild1PublicKey for future use
        GenuineChildPublicKey=GenuineChild1PublicKey;
        // do a decrypting test to ensure the secureKey is valid
        String testPlain = CryptoUtil.decryptAES(secureKey,testCipher);
        //assertTrue("EstablishSecureChannel testCipher",testPlain.equals("1234"));
    }
    public String sendSecure(String apduHeader, String apduData){
        // send command in legacy way if SecureChannel is not established
        if(secureKey==null){

            System.out.println("legacyPln:" + apduHeader + " " + apduData + " (" + (apduData.length()/2) + "Bytes)");
            String apduCommand = apduHeader + HexUtil.toHexString(apduData.length()/2,1) + apduData;
            System.out.println("apduCommand:" + apduCommand);
            byte[] bcmd = HexUtil.toByteArray(apduCommand);
            long startTime = System.currentTimeMillis();
            byte[] brtn ;
                    //card.send(0, bcmd, 0, bcmd.length);
            long endTime = System.currentTimeMillis();
            String apduResult = "";
                    //HexUtil.toHexString(brtn,brtn.length);
            System.out.println("legacyRtn:" + apduResult + " (" + (apduResult.length()/2 - 2) + "Bytes, " + (endTime - startTime) + "ms)");
            return apduResult;
        }

        System.out.println("securePln:" + apduHeader + " " + apduData + " (" + (apduData.length()/2) + "Bytes)");
        // get wrapped apdeCommand from SecureChannel core
        String[] apduCommand = sendSecureInner(apduHeader,apduData);
        int blockNumber = apduCommand.length;
        String[] apduResult = new String[blockNumber];
        // send all the apduCommand, save the return
        long startTime = System.currentTimeMillis();
        for(int i = 0 ; i < blockNumber ; i++){
            System.out.println("apduCommand[" + (i+1) + "/" + blockNumber + "]:" + apduCommand[i]);
            byte[] bcmd = HexUtil.toByteArray(apduCommand[i]);
//            byte[] brtn = card.send(0, bcmd, 0, bcmd.length);
//            apduResult[i] = HexUtil.toHexString(brtn,brtn.length);
//            System.out.println("rtn:" + apduResult[i]);
            //assertTrue("apduCommand", rtn.equals("9000"));
        }
        long endTime = System.currentTimeMillis();
        // pass apduResults to SecureChannel core to decrypt
        String stn = resultSecureInner(apduResult);

        System.out.println("secureRtn:" + stn + " (" + (stn.length()/2 - 2) + "Bytes, " + (endTime - startTime) + "ms)");
        return stn;
    }
    public String[] sendSecureInner(String apduHeader,String apduData){
        /*
        add salt and checksum, then encrypt origin header & data into a cipher
        real command to be send = 80CCXXXX + cipherData
        cipherData = cipherVersion + AES(apduHeader+hash+salt+apduData) with secureKey
        cipherVersion = 0x00 in this version
        apduHeader = 4Bytes of original APDU header, CLS+INS+P1+P2, e.g. 0x80520000
        apduData = original APDU payload with any length any content
        salt = 4Bytes of random data
        hash = SHA256(apduHeader+salt+apduData), 32Bytes
        '+' means concatenate
        */
        salt=CommonUtil.hexRandom(4);
        String hash=HashUtil.SHA256(apduHeader+salt+apduData);
        String cipherData = "00" + CryptoUtil.encryptAES(secureKey,apduHeader+hash+salt+apduData);
        //System.out.println("secureKey:" + secureKey + " (" + (secureKey.length()/2) + "Bytes)");
        //System.out.println("securePln:" + apduHeader + " " + apduData + " (" + (apduData.length()/2) + "Bytes) +" + salt + "," + hash);
        //System.out.println("secureCph:" + cipherData + " (" + (cipherData.length()/2) + "Bytes)");

        /*
        Divide cipherData into parts if it's too long to be send in one command
        e.g.80CC0003 + cipherData(1/3)
            80CC0103 + cipherData(2/3)
            80CC0203 + cipherData(3/3)
        80CC is the CLA & INS of SecureChannel
        P1 = index of this part, start from 00
        P2 = total number of parts
        If no dividing needed, use 80CC0001
        Length of each parts could be 0 <= x <= 250, don't need to be equal
        */

        // casually chosen blockSize, this could be 1~250
        int blockSize = 240;
        // number of parts, ceil(length/size)
        int blockNumber = (cipherData.length()/2-1)/blockSize + 1;

        String[] apduCommand = new String[blockNumber];

        for(int i = 0 ; i < blockNumber-1 ; i++){
            String commandHeader = "80CC" + HexUtil.toHexString(i,1) + HexUtil.toHexString(blockNumber,1);
            String commandData = cipherData.substring(i*blockSize*2, (i+1)*blockSize*2);
            String commandLength = HexUtil.toHexString(commandData.length()/2,1);
            //System.out.println("command:" + commandHeader + " " + commandData +" (" + (commandData.length()/2) + "Bytes)");
            apduCommand[i] = commandHeader + commandLength + commandData;
        }
        String commandHeader = "80CC" + HexUtil.toHexString(blockNumber-1,1) + HexUtil.toHexString(blockNumber,1);
        String commandData = cipherData.substring((blockNumber-1)*blockSize*2, cipherData.length());
        String commandLength = HexUtil.toHexString(commandData.length()/2,1);
        apduCommand[blockNumber-1] = commandHeader + commandLength + commandData;
        //System.out.println("command:" + commandHeader + " " + commandData +" (" + (commandData.length()/2) + "Bytes)");
        return apduCommand;
    }
    public String resultSecureInner(String[] apduResult) {
        int blockNumber = apduResult.length;
        for(int i = 0 ; i < blockNumber-1 ; i++){
           // assertTrue("SecureChannel non-completed result", apduResult[i].equals("9000"));
        }
        String rtn = apduResult[blockNumber-1];
        // decrypt the return data
        // returnData = cipherReturnData + 0x9000 if success (bare errorCode if failed)
        // cipherReturnData = checksumHash(32B) + salt(4B) + originReturnData
        if(rtn.substring(rtn.length() - 4,rtn.length()).equalsIgnoreCase("9000")){
            String decrypted = CryptoUtil.decryptAES(secureKey,rtn.substring(0,rtn.length() - 4));
            String decryptedHash = decrypted.substring(0,64);
            String decryptedSalt = decrypted.substring(64,72);
            String decryptedData = decrypted.substring(72,decrypted.length());
            //System.out.println("decrHash:" + decryptedHash );
            //System.out.println("decrSalt:" + decryptedSalt );
            //System.out.println("decrData:" + decryptedData );
            // returned salt should be same with sended salt

           // assertTrue(decryptedSalt.equalsIgnoreCase(salt));

            // reassemble returnData to origin form
            rtn = decryptedData + "9000";
        }

        return rtn;
    }

}