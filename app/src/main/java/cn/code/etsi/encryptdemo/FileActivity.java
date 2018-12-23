package cn.code.etsi.encryptdemo;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import com.leon.lfilepickerlibrary.LFilePicker;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;

import cn.code.etsi.encryptdemo.Utils.CipherUtils;
import cn.code.etsi.encryptdemo.Utils.FileUtils;

public class FileActivity extends AppCompatActivity {
    private EditText clearContet;
    private EditText decContent;

    private Button selFile;
    private Button encFile;
    private Button decFile;

    private final int REQUEST_FILE_PICK = 0;
    private String filePath;
    private byte[] encryptedBytes;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_file);

        clearContet = findViewById(R.id.editTextclearFile);
        decContent = findViewById(R.id.editDecryptFile);

        selFile = findViewById(R.id.selectFile);
        encFile = findViewById(R.id.encryptFile);
        decFile = findViewById(R.id.decryptFile);

        selFile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                String path = Environment.getExternalStoragePublicDirectory("").getAbsolutePath()+"/images";
//                new LFilePicker().withActivity(FileActivity.this)
//                        .withStartPath(path)
//                        .withRequestCode(REQUEST_FILE_PICK)
//                        .withTitle("choose your file")
//                        .start();

                Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                intent.setType("*/*");//设置类型，我这里是任意类型，任意后缀的可以这样写。
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                startActivityForResult(intent,REQUEST_FILE_PICK);

            }
        });

        encFile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
               InputStream in = getResources().openRawResource(R.raw.test);
                byte[]  content = FileUtils.getBytes(in);
                clearContet.setText(new String(content));
                encryptedBytes = CipherUtils.getInstance().encryptByte(content);

            }
        });


        decFile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try{
                    byte[] clear = CipherUtils.getInstance().decryptByte2File(encryptedBytes);
                    String fileContent = new String (clear);
                    decContent.setText(fileContent);
                }catch (Exception e){
                    System.out.println(e.toString());
                }

            }
        });
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        System.out.println("requestCode=" + requestCode + ", resultCode=" + resultCode);
        if (Activity.RESULT_OK == resultCode) {
            switch (requestCode) {
                case REQUEST_FILE_PICK:
                    Uri uri = data.getData();
                    filePath = uri.getPath();
                    break;
                default:
                    break;
            }
        }
        super.onActivityResult(requestCode, resultCode, data);
    }
}
