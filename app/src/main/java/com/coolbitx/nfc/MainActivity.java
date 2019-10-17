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
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import static com.coolbitx.nfc.utils.HexUtil.*;

public class MainActivity extends AppCompatActivity implements Listener{
    
    public static final String TAG = MainActivity.class.getSimpleName();

    private TextView txtResult;
    private EditText mEtBackupData;
    private EditText mEtPinCode;
    private Button mBtnBackup;
    private Button mBtnRestore;
    private Button mBtReset;

    private NFCWriteFragment mNfcWriteFragment;
    private NFCReadFragment mNfcReadFragment;

    private NfcAdapter mNfcAdapter;
    private Tag tag = null;

   // private String BACKUP_DATA ="0987654321";
   // private String HASHED_PIN_CODE = "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f";


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

        mEtPinCode =(EditText) findViewById(R.id.pinCodeTxt);
        mEtBackupData = (EditText) findViewById(R.id.backupTxt);
        mBtnBackup = (Button) findViewById(R.id.btn_backup);
        mBtnRestore = (Button) findViewById(R.id.btn_restore);
        mBtReset = (Button) findViewById(R.id.btn_reset);
        txtResult = (TextView) findViewById(R.id.txtResult);
        mBtnBackup.setOnClickListener(view -> backup());
        mBtnRestore.setOnClickListener(view -> restore());
        mBtReset.setOnClickListener( view -> reset());
    }

    private void initNFC(){
        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }
    public static String padLeft(String s, int len) {
        return String.format("%1$" + len + "s", s).replace(" ","0");
    }
    private String getHash_Pin_Code(){
        return getSHA256StrJava(mEtPinCode.getText().toString());
    }

    public static String getSHA256StrJava(String str){
        MessageDigest messageDigest;
        String encodeStr = "";
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes("UTF-8"));
            encodeStr = byte2Hex(messageDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return encodeStr;
    }

    private static String byte2Hex(byte[] bytes){
        StringBuffer stringBuffer = new StringBuffer();
        String temp = null;
        for (int i=0;i<bytes.length; i++  ){
            temp = Integer.toHexString(bytes[i] & 0xFF);
            if (temp.length()==1){
                //1得到一位的進行補0操作
                stringBuffer.append("0");
            }
            stringBuffer.append(temp);
        }
        return stringBuffer.toString();
    }


    private void backup() {
        String command = "80320500";
        byte[] _data = mEtBackupData.getText().toString().getBytes();
        String hexData = bytesToHex(_data);
        String HashPinCode = getHash_Pin_Code();
        int dataLength = HashPinCode.length() / 2 + hexData.length() / 2;
        command=  command+ padLeft(Integer.toHexString(dataLength),2);
        command = command+HashPinCode+hexData;
        setCommand(command);

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
        String command = "80340000";
        String HashPinCode = getHash_Pin_Code();
        int dataLength = HashPinCode.length() / 2 ;
        command=  command+padLeft(Integer.toHexString(dataLength),2);
        command = command+HashPinCode;
        setCommand(command);

    }

    private  void reset(){
        setCommand("80360000");
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
        IntentFilter[] nfcIntentFilter = new IntentFilter[]{techDetected,tagDetected,ndefDetected};

        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        if(mNfcAdapter!= null)
            mNfcAdapter.enableForegroundDispatch(this, pendingIntent, nfcIntentFilter, null);

    }

    @Override
    protected void onPause() {
        super.onPause();
        if(mNfcAdapter!= null)
            mNfcAdapter.disableForegroundDispatch(this);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

        Log.d(TAG, "onNewIntent: "+intent.getAction());

    }
    // 00A4040006C1C2C3C4C5C6
    private void setCommand(String cmd){

        if (tag!=null){

            try{
                byte [] first = hexStringToByteArray("00A4040006C1C2C3C4C5C6"); //3rd first cmd
                byte[] bytes = hexStringToByteArray(cmd);
                IsoDep techHandle = IsoDep.get(tag);
                techHandle.connect();
                techHandle.transceive(first);
                byte[] resultBytes = techHandle.transceive(bytes);
                if (resultBytes.length > 10)
                {
                    txtResult.setText("result:"+byteArrayToStr(resultBytes));
                }else{
                    txtResult.setText("result:" +byteArrayToHexStr(resultBytes));
                }

                techHandle.close();

                return;


            }catch (IOException ex){

                txtResult.setText("error:" + ex.toString());
            }
        }else{
            txtResult.setText("Can't get nfc tag info!");
        }
    }

    private static String byteArrayToHexStr(byte[] byteArray) {
        if (byteArray == null){
            return null;
        }
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[byteArray.length * 2];
        for (int j = 0; j < byteArray.length; j++) {
            int v = byteArray[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }



    private static String byteArrayToStr(byte[] byteArray) {

        if (byteArray == null) {
            return null;
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for(int i=0;i<byteArray.length;i++){
            int tmp =byteArray[i];
            if (tmp>0) output.write(byteArray[i]);
        }
        byte[] newArray = output.toByteArray();


        String str ;
        try {
            str = new String(newArray,"UTF-8");
        }catch (IOException ex){
            str = ex.toString();
        }

        return str;
    }


}
