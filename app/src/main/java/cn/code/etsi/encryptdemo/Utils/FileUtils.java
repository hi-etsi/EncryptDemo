package cn.code.etsi.encryptdemo.Utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

public class FileUtils {

    public static byte[] getBytes(String path){
        File imageFile = new File(path);
        try {
            FileInputStream fis = new FileInputStream(imageFile);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int offSet = 0;
            while ((fis.read(buffer)) != -1) {
                out.write(buffer, offSet, buffer.length);
                offSet += buffer.length;
            }
            return out.toByteArray();
        }catch (Exception e){
            System.out.println(e.toString());
            return null;
        }
    }

    public static byte[] getBytes(InputStream fis){
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[fis.available()];
            fis.read(buffer);
            out.write(buffer,0,buffer.length);
            return out.toByteArray();
//            int offSet = 0;
//            int len =0;
//            while ((len=fis.read(buffer)) != -1) {
//                out.write(buffer, offSet, len);
//                offSet += buffer.length;
//            }
//            return out.toByteArray();
        }catch (Exception e){
            System.out.println(e.toString());
            return null;
        }

    }

}