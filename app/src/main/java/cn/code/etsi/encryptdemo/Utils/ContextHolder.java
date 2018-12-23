package cn.code.etsi.encryptdemo.Utils;

import android.content.Context;

import cn.code.etsi.encryptdemo.R;

public class ContextHolder {
   private static Context applicationContext;
   private   static String privateKey;
   private  static String publicKey;

    public static void initial(Context context){
        applicationContext = context;
        setPrivateKey();
        setPublicKey();
    }

    public static Context getContext(){
        return applicationContext;
    }

    private static void setPrivateKey(){
        privateKey = applicationContext.getString(R.string.privKey);
    }

    private static void setPublicKey(){
        publicKey = applicationContext.getString(R.string.pubKey);
    }

    public static String getPublicKey(){
       return publicKey;
    }
    public static String getPrivateKey(){
        return privateKey;
    }
}
