package com.goodl.aes.test;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;

import com.goodl.aes.FooTools;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        findViewById(R.id.btn_test).setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        String text = "abc_-=.,123扫地阿姨发现你的代码有Bug";
        String textEnc = FooTools.method01(text);
        String textDec = FooTools.method02(textEnc);

        Log.d("aes", "text: " + text);
        Log.d("aes", "text 加码: " + textEnc);
        Log.d("aes", "text 解密: " + textDec);
    }

}
