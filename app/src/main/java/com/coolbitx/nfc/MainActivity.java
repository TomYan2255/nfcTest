package com.coolbitx.nfc;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;

import android.support.multidex.MultiDex;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static com.coolbitx.nfc.utils.HexUtil.*;

import com.coolbitx.nfc.utils.CommonUtil;
import com.coolbitx.nfc.utils.CryptoUtil;
import com.coolbitx.nfc.utils.HashUtil;
import com.coolbitx.nfc.utils.HexUtil;
import com.coolbitx.nfc.utils.KeyUtil;

public class MainActivity extends AppCompatActivity implements Listener {

    public static final String TAG = MainActivity.class.getSimpleName();

    private TextView txtResult;
    private EditText mEtBackupData;
    private EditText mEtPinCode;
    private Button mBtnBackup;
    private Button mBtnRestore;
    private Button mBtReset;
    private IsoDep techHandle = null;
    private NFCWriteFragment mNfcWriteFragment;
    private NFCReadFragment mNfcReadFragment;

    private NfcAdapter mNfcAdapter;
    private Tag tag = null;
    protected static String secureKey = null;
    protected static final String GenuineMasterChainCode_NonInstalled = "611c6956ca324d8656b50c39a0e5ef968ecd8997e22c28c11d56fb7d28313fa3";
    protected static final String GenuineMasterPublicKey_NonInstalled = "04e720c727290f3cde711a82bba2f102322ab88029b0ff5be5171ad2d0a1a26efcd3502aa473cea30db7bc237021d00fd8929123246a993dc9e76ca7ef7f456ade";
    protected static final String GenuineMasterChainCode_Test = "f5a0c5d9ffaee0230a98a1cc982117759c149a0c8af48635776135dae8f63ba4";
    protected static final String GenuineMasterPublicKey_Test = "0401e3a7de779276ef24b9d5617ba86ba46dc5a010be0ce7aaf65876402f6a53a5cf1fecab85703df92e9c43e12a49f33370761153216df8291b7aa2f1a775b086";
    private Boolean useSecureChanel = true;
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initViews();
        initNFC();
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        MultiDex.install(this);
    }


    private void initViews() {
        mEtPinCode = (EditText) findViewById(R.id.pinCodeTxt);
        mEtBackupData = (EditText) findViewById(R.id.backupTxt);
        mBtnBackup = (Button) findViewById(R.id.btn_backup);
        mBtnRestore = (Button) findViewById(R.id.btn_restore);
        mBtReset = (Button) findViewById(R.id.btn_reset);
        txtResult = (TextView) findViewById(R.id.txtResult);
        mBtnBackup.setOnClickListener(view -> backup());
        mBtnRestore.setOnClickListener(view -> restore());
        mBtReset.setOnClickListener(view -> reset());
    }

    private void initNFC() {
        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }

    public static String padLeft(String s, int len) {
        return String.format("%1$" + len + "s", s).replace(" ", "0");
    }

    private String getHash_Pin_Code() {
        return getSHA256StrJava(mEtPinCode.getText().toString());
    }

    public static String getSHA256StrJava(String str) {

        String encodeStr = "";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(str.getBytes(StandardCharsets.UTF_8));
            encodeStr = HexUtil.bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return encodeStr;
    }

    private void sendCmdWithSecureChannel(String apduHeader, String cmd) {

        Log.e("'apduHeader'", apduHeader);
        Log.e("'cmd'", cmd);
        try {
            String sessionAppPrivateKey = CommonUtil.hexRandom(32);
            String sessionAppPublicKey = KeyUtil.getPublicKey(sessionAppPrivateKey);
            String command = "80CE000041";
            command = command + sessionAppPublicKey;
            byte[] bytes = hexStringToByteArray(command);
            techHandle = IsoDep.get(tag);
            if (techHandle.isConnected()) techHandle.close();
            techHandle.connect();
            byte[] resultBytes = techHandle.transceive(bytes);
            String ret = byteArrayToHexStr(resultBytes);
            String installType = ret.substring(0, 4);
            int cardNameLength = HexUtil.toInt(ret.substring(4, 8));
            String cardNameHex = ret.substring(8, 8 + cardNameLength * 2);
            ret = ret.substring(8 + cardNameLength * 2, ret.length());
            String nonceIndex = ret.substring(0, 64);
            String GenuineMasterPublicKey = null;
            String GenuineMasterChainCode = null;
            switch (installType) {
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
                    throw new Exception("Error");
            }

            String GenuineChild1PublicKey = KeyUtil.getChildPublicKey(GenuineMasterPublicKey, GenuineMasterChainCode, cardNameHex);
            String GenuineChild1ChainCode = KeyUtil.getChildChainCode(GenuineMasterPublicKey, GenuineMasterChainCode, cardNameHex);
            String GenuineChild2PublicKey = KeyUtil.getChildPublicKey(GenuineChild1PublicKey, GenuineChild1ChainCode, nonceIndex);
            secureKey = KeyUtil.getEcdhKey(GenuineChild2PublicKey, sessionAppPrivateKey);
            String[] apduCommand = sendSecureInner(apduHeader, cmd);
            int blockNumber = apduCommand.length;
            String[] apduResult = new String[blockNumber];
            String tmp = "";
            for (int i = 0; i < blockNumber; i++) {
                System.out.println("apduCommand[" + (i + 1) + "/" + blockNumber + "]:" + apduCommand[i]);
                byte[] bcmd = HexUtil.toByteArray(apduCommand[i]);
                byte[] resultByte = techHandle.transceive(bcmd);
                apduResult[i] = HexUtil.toHexString(resultByte, resultByte.length);
                String result = byteArrayToHexStr(resultByte);
                System.out.println("rtn:" + byteArrayToHexStr(resultByte));
                if (result.length() == 4) {  //cmd
                    tmp = tmp + byteArrayToHexStr(resultByte);
                } else {
                    tmp = tmp + byteArrayToStr(hexStringToByteArray(resultSecureInner(apduResult[i])));
                }
            }

            txtResult.setText("result:" + tmp);


        } catch (Exception ex) {
            Log.e("ex", ex.toString());
        } finally {
            try {
                techHandle.close();
            } catch (Exception ex) {
                Log.e("ex", ex.toString());
            }

        }
    }

    private void backup() {
        String apduHeader = "80320500";
        String command = "";
        byte[] _data = mEtBackupData.getText().toString().getBytes();
        String hexData = bytesToHex(_data);
        String HashPinCode = getHash_Pin_Code();
        int dataLength = HashPinCode.length() / 2 + hexData.length() / 2;
        if (!useSecureChanel) {
            command = command + padLeft(Integer.toHexString(dataLength), 2);
        }

        command = command + HashPinCode + hexData;
        if (!useSecureChanel) {
            sendCommand(command);
        } else {
            sendCmdWithSecureChannel(apduHeader, command);
        }

//        isWrite = true;
//
//        mNfcWriteFragment = (NFCWriteFragment) getFragmentManager().findFragmentByTag(NFCWriteFragment.TAG);
//
//        if (mNfcWriteFragment == null) {
//
//            mNfcWriteFragment = NFCWriteFragment.newInstance();
//        }
//        mNfcWriteFragment.show(getFragmentManager(),NFCWriteFragment.TAG);

    }

    private void restore() {

        String apduHeader = "80340000";
        String command = "";
        String HashPinCode = getHash_Pin_Code();

        if (!useSecureChanel) {
            int dataLength = HashPinCode.length() / 2;
            command = command + padLeft(Integer.toHexString(dataLength), 2);
        }
        command = command + HashPinCode;

        if (!useSecureChanel) {
            sendCommand(command);
        } else {
            sendCmdWithSecureChannel(apduHeader, command);
        }
        // sendCmdWithSecureChannel(apduHeader, command);

    }

    private void reset() {

        if (!useSecureChanel) {
            sendCommand("80360000");
        } else {
            sendCmdWithSecureChannel("80360000", "");
        }

    }

    @Override
    public void onDialogDisplayed() {

    }

    @Override
    public void onDialogDismissed() {

    }

    @Override
    protected void onResume() {
        super.onResume();
        IntentFilter tagDetected = new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED);
        IntentFilter ndefDetected = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
        IntentFilter techDetected = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);
        IntentFilter[] nfcIntentFilter = new IntentFilter[]{techDetected, tagDetected, ndefDetected};

        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        if (mNfcAdapter != null)
            mNfcAdapter.enableForegroundDispatch(this, pendingIntent, nfcIntentFilter, null);

    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableForegroundDispatch(this);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

        Log.d(TAG, "onNewIntent: " + intent.getAction());

    }

    // 00A4040006C1C2C3C4C5C6
    private void sendCommand(String cmd) {

        if (tag != null) {

            try {
                byte[] first = hexStringToByteArray("00A4040006C1C2C3C4C5C6"); //3rd first cmd
                byte[] bytes = hexStringToByteArray(cmd);
                IsoDep techHandle = IsoDep.get(tag);
                techHandle.connect();
                techHandle.transceive(first);
                byte[] resultBytes = techHandle.transceive(bytes);
                if (resultBytes.length > 10) {
                    txtResult.setText("result:" + byteArrayToStr(resultBytes));
                } else {
                    txtResult.setText("result:" + byteArrayToHexStr(resultBytes));
                }

                techHandle.close();

                return;


            } catch (IOException ex) {

                txtResult.setText("error:" + ex.toString());
            }
        } else {
            txtResult.setText("Can't get nfc tag info!");
        }
    }

    private static String byteArrayToHexStr(byte[] byteArray) {
        if (byteArray == null) {
            return null;
        }

        char[] hexChars = new char[byteArray.length * 2];
        for (int j = 0; j < byteArray.length; j++) {
            int v = byteArray[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }


    private static String byteArrayToStr(byte[] byteArray) {

        if (byteArray == null) {
            return null;
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (int i = 0; i < byteArray.length; i++) {
            int tmp = byteArray[i];
            if (tmp > 0) output.write(byteArray[i]);
        }
        byte[] newArray = output.toByteArray();


        String str;
        try {
            str = new String(newArray, "UTF-8");
        } catch (IOException ex) {
            str = ex.toString();
        }

        return str;
    }


    public String[] sendSecureInner(String apduHeader, String apduData) {
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
        String salt = CommonUtil.hexRandom(4);
        String hash = HashUtil.SHA256(apduHeader + salt + apduData);
        String cipherData = "00" + CryptoUtil.encryptAES(secureKey, apduHeader + hash + salt + apduData);
        System.out.println("secureKey:" + secureKey + " (" + (secureKey.length() / 2) + "Bytes)");
        System.out.println("securePln:" + apduHeader + " " + apduData + " (" + (apduData.length() / 2) + "Bytes) +" + salt + "," + hash);
        System.out.println("secureCph:" + cipherData + " (" + (cipherData.length() / 2) + "Bytes)");

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
        int blockNumber = (cipherData.length() / 2 - 1) / blockSize + 1;

        String[] apduCommand = new String[blockNumber];

        for (int i = 0; i < blockNumber - 1; i++) {
            String commandHeader = "80CC" + HexUtil.toHexString(i, 1) + HexUtil.toHexString(blockNumber, 1);
            String commandData = cipherData.substring(i * blockSize * 2, (i + 1) * blockSize * 2);
            String commandLength = HexUtil.toHexString(commandData.length() / 2, 1);
            System.out.println("command:" + commandHeader + " " + commandData + " (" + (commandData.length() / 2) + "Bytes)");
            apduCommand[i] = commandHeader + commandLength + commandData;
        }
        String commandHeader = "80CC" + HexUtil.toHexString(blockNumber - 1, 1) + HexUtil.toHexString(blockNumber, 1);
        String commandData = cipherData.substring((blockNumber - 1) * blockSize * 2, cipherData.length());
        String commandLength = HexUtil.toHexString(commandData.length() / 2, 1);
        apduCommand[blockNumber - 1] = commandHeader + commandLength + commandData;
        System.out.println("command:" + commandHeader + " " + commandData + " (" + (commandData.length() / 2) + "Bytes)");
        return apduCommand;
    }

    public String resultSecureInner(String apduResult) {
        //int blockNumber = apduResult.length;
        String rtn = apduResult;
        if (rtn.substring(rtn.length() - 4, rtn.length()).equalsIgnoreCase("9000")) {
            String decrypted = CryptoUtil.decryptAES(secureKey, rtn.substring(0, rtn.length() - 4));
            String decryptedData = decrypted.substring(72, decrypted.length());
            rtn = decryptedData;    //hex > string
        } else if (rtn.substring(rtn.length() - 4, rtn.length()).equalsIgnoreCase("6350")) {
            String decrypted = CryptoUtil.decryptAES(secureKey, rtn.substring(0, rtn.length() - 4));
            String decryptedData = decrypted.substring(72, decrypted.length());
            rtn = decryptedData;
        }

        return rtn;
    }

}
