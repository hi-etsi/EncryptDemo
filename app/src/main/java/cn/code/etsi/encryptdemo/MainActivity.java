package cn.code.etsi.encryptdemo;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import cn.code.etsi.encryptdemo.Utils.CipherUtils;
import cn.code.etsi.encryptdemo.Utils.ContextHolder;

public class MainActivity extends AppCompatActivity {

    private EditText clearText;
    private EditText decryptText;
    private EditText encryptText;
    private Button  doEncrypt;
    private Button  doDecrypt;
    private boolean flag = false;

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ContextHolder.initial(getApplicationContext());
        setContentView(R.layout.activity_main);

//        // Example of a call to a native method
//        TextView tv = (TextView) findViewById(R.id.sample_text);
//        tv.setText(stringFromJNI());

        clearText = (EditText) findViewById(R.id.editClearText);
        encryptText = (EditText) findViewById(R.id.editEncrypt);
        decryptText = (EditText) findViewById(R.id.editAfterDecrypt);
        doEncrypt = (Button) findViewById(R.id.encrypt);
        doDecrypt = (Button) findViewById(R.id.decrypt);

        doEncrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (flag){
                    return ;
                }
               String text = clearText.getText().toString();
                String content = CipherUtils.getInstance().encryptText(text);
                encryptText.setText(content);
                flag = true;
            }
        });

        doDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (!flag){
                    return;
                }
                String toDecrypt = encryptText.getText().toString();
                String content = CipherUtils.getInstance().decryptText(toDecrypt);
                decryptText.setText(content);
                flag = false;
            }
        });


        Button trans2Pic = (Button) findViewById(R.id.transfer2PicActivity);
        trans2Pic.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this,PicActivity.class));
            }
        });

        Button trans2File = (Button) findViewById(R.id.trans2File);
        trans2File.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this,FileActivity.class));
            }
        });
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}
