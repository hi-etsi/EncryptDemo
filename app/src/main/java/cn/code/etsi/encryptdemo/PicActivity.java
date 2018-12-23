package cn.code.etsi.encryptdemo;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.provider.MediaStore;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.DisplayMetrics;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;

import com.leon.lfilepickerlibrary.LFilePicker;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.List;

import cn.code.etsi.encryptdemo.Utils.BitmapUtils;
import cn.code.etsi.encryptdemo.Utils.CipherUtils;
import cn.code.etsi.encryptdemo.Utils.FileUtils;

public class PicActivity extends AppCompatActivity {
    private ImageView beforeEnc;
    private ImageView afterDec;
    private Button enc;
    private Button dec;
    private Button selectPic;
    private byte[] encryptData;

    private final int REQUEST_FILE_PICK =0;
    private final int REQUEST_IMAGE_PICK =1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pic);



        beforeEnc = findViewById(R.id.imagebeforeEncrypt);
        afterDec = findViewById(R.id.imageafterDecrypt);
        enc = findViewById(R.id.picEncrypt);
        dec = findViewById(R.id.picDecrypt);
        selectPic = findViewById(R.id.selectPic);


        selectPic.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent photoPickerIntent = new Intent(Intent.ACTION_PICK, null);
                photoPickerIntent.setDataAndType(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, "image/*");
                startActivityForResult(photoPickerIntent, REQUEST_IMAGE_PICK);
            }
        });


        enc.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                new LFilePicker().withActivity(PicActivity.this)
//                        .withRequestCode(REQUEST_FILE_PICK)
//                        .withTitle("choose your file")
//                        .start();
          InputStream in = getResources().openRawResource(R.raw.timg);

          beforeEnc.setImageBitmap(BitmapFactory.decodeStream(in));
           String filePath = getResources().getResourceEntryName(R.raw.timg);
           InputStream is = getResources().openRawResource(R.raw.timg);
         encryptData = CipherUtils.getInstance().encryptByte(FileUtils.getBytes(is));
            }
        });


        dec.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                byte[] clear = CipherUtils.getInstance().decryptByte2File(encryptData);
                Bitmap bitmap =  BitmapUtils.getBitmapByBytes(clear);
                afterDec.setImageBitmap(bitmap);
            }
        });

    }
    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        System.out.println("requestCode=" + requestCode + ", resultCode=" + resultCode);
        if (Activity.RESULT_OK == resultCode) {
            switch (requestCode) {
                case REQUEST_FILE_PICK:
                    //需要判定文件大小
                    List<String> list = data.getStringArrayListExtra("paths");
                    if (list.size() > 1) {
                        for (String path : list) {
                            ;
                        }
                    } else {
                        encryptFile(list.get(0));
                    }
                    break;
                case REQUEST_IMAGE_PICK:
                   String picPath = getRealPathFromURI(this,data.getData());
                   setBitmap(picPath,enc);
                default:
                    break;
            }
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    private void encryptFile(String path){
        DisplayMetrics dm = getResources().getDisplayMetrics();
           //获取图片压缩后的字节数组
            byte[] userData = FileUtils.getBytes(path);
            encryptData = CipherUtils.getInstance().encryptByte(userData);
        }


    /**
     * 根据 Uri 获取文件所在的位置
     *
     * @param context
     * @param contentUri
     * @return
     */
    private String getRealPathFromURI(Context context, Uri contentUri) {
        if (contentUri.getScheme().equals("file")) {
            return contentUri.getEncodedPath();
        } else {
            Cursor cursor = null;
            try {
                String[] proj = {MediaStore.Images.Media.DATA};
                cursor = context.getContentResolver().query(contentUri, proj, null, null, null);
                if (null != cursor) {
                    int column_index = cursor.getColumnIndexOrThrow(MediaStore.Images.Media.DATA);
                    cursor.moveToFirst();
                    return cursor.getString(column_index);
                } else {
                    return "";
                }
            } finally {
                if (cursor != null) {
                    cursor.close();
                }
            }
        }
    }

    private void setBitmap(String path, View view){
        FileInputStream in = null;
        try {
             in = new FileInputStream(path);
             Bitmap bitmap = BitmapFactory.decodeStream(in);
             ImageView iv = (ImageView)view;
             iv.setImageBitmap(bitmap);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

}
