
客户端数据进行加密保护还是很有必要的。

对Android来说，一般的方式有：
- 在 java 代码里进行加密
- 在 native 代码里进行加密

对于第一种，安全性不高，应用容易被反编译，看到代码逻辑。当然可以进行加固，但是也有脱壳工具，真是道高一尺，魔高一丈。
对于第二种，安全性比第一种高。看不到代码。但是 jni 接口是直接暴露的，别人可以直接拿 so 直接使用。可以做签名验证，防止二次打包等。

加密方式也有很多，如RSA加密，MD5加密，AES加密，DES加密等等
这里我们使用的是 AES CBC Pkcs5Padding。具体代码可参考文章最后的源码。

----

### 0x01
首先，我们要创建一个 Android 工程，还有一个 AesUtils.java：
```java
public class AesUtils {

    static {
        System.loadLibrary("aesLib");
    }

    // AES加密, CBC, PKCS5Padding
    public static native String encrypt(String str);

    // AES解密, CBC, PKCS5Padding
    public static native String decrypt(String str);
}
```

还有对应的 c++ 文件 aes_lib.cpp：
```cpp
#include <jni.h>
#include <string>
#include "aes_utils.h"
#include "tools.h"


#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jstring JNICALL Java_com_goodl_aes_AesUtils_encrypt(JNIEnv *env, jclass jcls, jstring str_) {
    if (str_ == nullptr) return nullptr;

    const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
    char *result = AES_128_CBC_PKCS5_Encrypt(str);

    env->ReleaseStringUTFChars(str_, str);

    jstring jResult = getJString(env, result);
    free(result);

    return jResult;
}

JNIEXPORT jstring JNICALL Java_com_goodl_aes_AesUtils_decrypt(JNIEnv *env, jclass jcls, jstring str_) {
    if (str_ == nullptr) return nullptr;

    const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
    char *result = AES_128_CBC_PKCS5_Decrypt(str);

    env->ReleaseStringUTFChars(str_, str);

    jstring jResult = getJString(env, result);
    free(result);

    return jResult;
}

#ifdef __cplusplus
}
#endif
```

其中，```getJString``` 函数在 tools 中，负责将 c 字符串转为 java 字符串，最后记得释放内存。其他文件这里省略，可自行参考源码。

我们看下运行结果：
```
D/aes: text: abc_-=.,123扫地阿姨发现你的代码有Bug
D/aes: text 加密: 9aba6ccf2b80ca251c1186508e019ca52d7e277dc0b4b4420440ed491fb2aeb8635dce02d1bb174363ad919ae261d10f
D/aes: text 解密: abc_-=.,123扫地阿姨发现你的代码有Bug
```

然后可以在 [http://ctf.ssleye.com/caes.html](http://ctf.ssleye.com/caes.html) 验证：
![QQ20190917-154909@2x.png](https://upload-images.jianshu.io/upload_images/6349226-cabddb3b4a3e7bad.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/700)


结果一致，万事大吉 ？？？
一切才刚刚开始，目前为止，我们已经实现了加解密，但是安全呢？
对AES加密来说，最重要的就是密钥 key 和偏移量 iv 了。
我们打开神器 ida，再用神奇的 F5：
![ida1.png](https://upload-images.jianshu.io/upload_images/6349226-8ed6058dc43fe733.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/700)

然后再看AES_128_CBC_PKCS5_Encrypt：
![ida2.png](https://upload-images.jianshu.io/upload_images/6349226-7c7e6acb48258c03.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/700)

再看看 off_6008 ：
![ida3.png](https://upload-images.jianshu.io/upload_images/6349226-e49b7e246e9d3dbe.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/700)


我们的密钥和偏移量就这么暴露了，为什么会这样？因为我们的 key 和 iv 没有任何保护，不管是宏定义还是字符串常量，都很容易被反汇编工具找到 ：
```c
#define AES_KEY "goodl-aes-key123"
#define AES_IV  "goodl-aes-iv1234"

static const char *AES_KEY = "goodl-aes-key123";
static const char *AES_IV = "goodl-aes-iv1234";
```

----

### 0x02

那么我们修改一下，对 key 和 iv 进行一些保护：
```c
static const uint8_t *getKey() {
    const int len = 16;
    uint8_t *src = malloc(len + 1);

    for (int i = 0; i < len; ++i) {
        switch (i) {
            case 0:  src[i] = 'g'; break;
            case 1:  src[i] = 'o'; break;
            case 2:  src[i] = 'o'; break;
            case 3:  src[i] = 'd'; break;
            case 4:  src[i] = 'l'; break;
            case 5:  src[i] = '-'; break;
            case 6:  src[i] = 'a'; break;
            case 7:  src[i] = 'e'; break;
            case 8:  src[i] = 's'; break;
            case 9:  src[i] = '-'; break;
            case 10: src[i] = 'k'; break;
            case 11: src[i] = 'e'; break;
            case 12: src[i] = 'y'; break;
            case 13: src[i] = '1'; break;
            case 14: src[i] = '2'; break;
            case 15: src[i] = '3'; break;
        }
    }
    src[len] = '\0';
    return src;
}

static const uint8_t *getIV() {
    const int len = 16;
    uint8_t *src = malloc(len + 1);

    for (int i = 0; i < len; ++i) {
        switch (i) {
            case 0:  src[i] = 'g'; break;
            case 1:  src[i] = 'o'; break;
            case 2:  src[i] = 'o'; break;
            case 3:  src[i] = 'd'; break;
            case 4:  src[i] = 'l'; break;
            case 5:  src[i] = '-'; break;
            case 6:  src[i] = 'a'; break;
            case 7:  src[i] = 'e'; break;
            case 8:  src[i] = 's'; break;
            case 9:  src[i] = '-'; break;
            case 10: src[i] = 'i'; break;
            case 11: src[i] = 'v'; break;
            case 12: src[i] = '1'; break;
            case 13: src[i] = '2'; break;
            case 14: src[i] = '3'; break;
            case 15: src[i] = '4'; break;
        }
    }
    src[len] = '\0';
    return src;
}
```

然后再看下ida：
![ida4.png](https://upload-images.jianshu.io/upload_images/6349226-3a62da3ebffe4164.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/700)

这样就不能直接看出 key 和 iv 了，起到了一定的保护作用。还可以将 key 和 iv 先 base64 编码，放入数组，再 base64 解码后返回。

----

### 0x03

我们还可以进一步增强 so 的安全性，比如代码的混淆和加入花指令，以及 so 的加固。

花指令是由设计者特别构思，希望使反汇编的时候出错，让破解者无法清楚正确地反汇编程序的内容，迷失方向。有兴趣的话可以自行搜索一下花指令。

先说混淆吧，我们可以通过宏定义的方式来混淆。以 aes_utils 为例：
```c
#define AES_128_CBC_PKCS5_Encrypt  ll11l1l1ll
#define AES_128_CBC_PKCS5_Decrypt  ll11lll11l
#define getKey                     ll11lll1l1
#define getIV                      ll11l1l1l1
#define getPaddingInput            ll11l1l11l
#define findPaddingIndex           lll1l1l1l1
#define removePadding              ll11l1llll
```


----

### 0x04

然后是花指令，花指令工具类 junk.h：
```c
#ifndef _JUNK_H_
#define _JUNK_H_

#define JUNK_CODE        //是否插入垃圾代码的开关
#ifdef JUNK_CODE

#define junk_fun0                 li11li1o0
#define junk_fun1                 li11li1o1
#define junk_fun2                 li11li1o2
#define junk_fun3                 li11li1o3

static inline int junk_fun0(void) {
    volatile int i = 138, j = 1949;

    if ((i++) % 2 > 0) j *= i;
    if (j < 0) i *= 2;
    else return 0;

    i = 1;
    while (i++ < 2) {
        j /= i;
        j++;
        i++;
    }
    return i;
}

static inline int junk_fun1(void) {
    volatile int i = 21, j = 75;

    if ((i--) % 3 > 0) j *= i;
    if (j > 1) i *= 3;
    else return 1;

    i = 1;
    while (i++ < 3) {
        j /= i;
        j--;
        i++;
    }
    return j;
}

static inline int junk_fun2(void) {
    volatile int i = 56, j = 17;

    if ((i--) % 5 > 0) j *= i;
    if (j > 2) i *= 5;
    else return 0;

    i = 1;
    while (i++ < 5) {
        j *= i;
        j += 3;
        i += 3;
    }
    return i;
}

static inline int junk_fun3(void) {
    volatile int i = 1909, j = 131;

    if ((i--) % 7 > 0) j *= i;
    if (j > 3) i *= 7;
    else return 1;

    i = 1;
    while (i++ < 7) {
        j /= i;
        j -= 5;
        i += 5;
    }
    return i;
}

#define _JUNK_FUN_0 {if(junk_fun2())junk_fun1();if(junk_fun0()) junk_fun3();if(junk_fun1()) junk_fun2();if(junk_fun3()) junk_fun1(); \
                       if(junk_fun1())junk_fun0();if(junk_fun2()) junk_fun3();if(junk_fun3()) junk_fun1();if(junk_fun1()) junk_fun0();}
#define _JUNK_FUN_1 {if(junk_fun3())junk_fun1();if(junk_fun1()) junk_fun2();if(junk_fun2()) junk_fun0();if(junk_fun0()) junk_fun1(); \
                       if(junk_fun2())junk_fun1();if(junk_fun0()) junk_fun3();if(junk_fun1()) junk_fun2();if(junk_fun3()) junk_fun1();}
#define _JUNK_FUN_2 {if(junk_fun1())junk_fun0();if(junk_fun2()) junk_fun3();if(junk_fun3()) junk_fun1();if(junk_fun1()) junk_fun0(); \
                       if(junk_fun0())junk_fun2();if(junk_fun3()) junk_fun0();if(junk_fun0()) junk_fun3();if(junk_fun2()) junk_fun3();}
#define _JUNK_FUN_3 {if(junk_fun0())junk_fun2();if(junk_fun3()) junk_fun0();if(junk_fun0()) junk_fun3();if(junk_fun2()) junk_fun3(); \
                       if(junk_fun3())junk_fun1();if(junk_fun1()) junk_fun2();if(junk_fun2()) junk_fun0();if(junk_fun0()) junk_fun1();}

#else

#define _JUNK_FUN_0 {}
#define _JUNK_FUN_1 {}
#define _JUNK_FUN_2 {}
#define _JUNK_FUN_3 {}

#endif
#endif
```

做完这些我们再来看一下效果：
![ida5.png](https://upload-images.jianshu.io/upload_images/6349226-2bd11603d8c77736.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/700)

之前可以清晰看到的函数名，现在全变成了 o000OO0O，qqppqp，ll11l1llll，bbbddbdbb 这些没有含义又相似度极高的名称了。总之看起来废眼，头疼。长时间看还容易引起头晕，脑胀，恶心反胃等不良反应。

----

### 0x05

目前为止，安全性有了一定的提升，但感觉还不够，因为我们的 jni 入口还是可以一眼就看出来的。```Java_com_goodl_aes_AesUtils_encrypt``` 和 ```Java_com_goodl_aes_AesUtils_decrypt ``` 实在是鹤立鸡群，太扎眼。

解决方法：
- java 层的类名和方法名就不要那么规范了，人肉混淆
- 改为动态注册（有兴趣的可以搜下 jni 动态注册）
- so 名字也换掉，带个 aes，谁都知道是干什么的了

AesUtils.java 改为 FooTools.java
```java
public class FooTools {

    static {
        System.loadLibrary("fooLib");
    }

    // AES加密, CBC, PKCS5Padding
    public static native String method01(String str);

    // AES解密, CBC, PKCS5Padding
    public static native String method02(String str);
}
```

aes_lib.cpp 改为 foo_tools.cpp，使用动态注册:  
```c
#include <jni.h>
#include <string>
#include "aes_utils.h"
#include "tools.h"
#include "junk.h"

#define JNIREG_CLASS "com/goodl/aes/FooTools"
#define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jstring JNICALL method01(JNIEnv *env, jclass jcls, jstring str_) {
    if (str_ == nullptr) return nullptr;

    const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
    char *result = AES_128_CBC_PKCS5_Encrypt(str);

    env->ReleaseStringUTFChars(str_, str);

    jstring jResult = getJString(env, result);
    free(result);

    return jResult;
}

JNIEXPORT jstring JNICALL method02(JNIEnv *env, jclass jcls, jstring str_) {
    if (str_ == nullptr) return nullptr;

    const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
    char *result = AES_128_CBC_PKCS5_Decrypt(str);

    env->ReleaseStringUTFChars(str_, str);

    jstring jResult = getJString(env, result);
    free(result);

    return jResult;
}

static JNINativeMethod method_table[] = {
        {"func0x01", "(Ljava/lang/String;)Ljava/lang/String;", (void *) method01},
        {"func0x02", "(Ljava/lang/String;)Ljava/lang/String;", (void *) method02},
};

static int registerMethods(JNIEnv *env, const char *className,
                           JNINativeMethod *gMethods, int numMethods) {
    jclass clazz = env->FindClass(className);
    if (clazz == nullptr) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    _JUNK_FUN_0

    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    assert(env != nullptr);

    // 注册native方法
    if (!registerMethods(env, JNIREG_CLASS, method_table, NELEM(method_table))) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}

#ifdef __cplusplus
}
#endif
```

现在 so 的安全性又有提高。我们还可以做什么？
- 验证签名，签名不一致就报错或是返回空
- 防调试
- 防 Xposed
- 对 so 加固


