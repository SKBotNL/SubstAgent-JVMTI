#ifndef FIS_HOOK_H
#define FIS_HOOK_H

#include <jvmti.h>
#include <jni.h>

typedef void (JNICALL *open0_t)(JNIEnv*, jobject, jstring);
typedef jint (JNICALL *readBytes_t)(JNIEnv*, jobject, jbyteArray, jint, jint);
typedef jint (JNICALL *read0_t)(JNIEnv*, jobject);
typedef jlong (JNICALL *length0_t)(JNIEnv*, jobject);
typedef jlong (JNICALL *position0_t)(JNIEnv*, jobject);
typedef jlong (JNICALL *skip0_t)(JNIEnv*, jobject, jlong);
typedef jint (JNICALL *available0_t)(JNIEnv*, jobject);
typedef void (JNICALL *close_t)(JNIEnv*, jobject);
extern readBytes_t fis_real_readBytes;
extern open0_t fis_real_open0;
extern read0_t fis_real_read0;
extern length0_t fis_real_length0;
extern position0_t fis_real_position0;
extern skip0_t fis_real_skip0;
extern available0_t fis_real_available0;
extern close_t fis_real_close;

jint JNICALL fis_readBytes_hook(JNIEnv* env, jobject thiz, jbyteArray buf, jint off, jint len);
void JNICALL fis_open0_hook(JNIEnv* env, jobject thiz, jstring jpath);
jint JNICALL fis_read0_hook(JNIEnv* env, jobject thiz);
jlong JNICALL fis_length0_hook(JNIEnv* env, jobject thiz);
jlong JNICALL fis_position0_hook(JNIEnv* env, jobject thiz);
jlong JNICALL fis_skip0_hook(JNIEnv* env, jobject thiz, jlong n);
jint JNICALL fis_available0_hook(JNIEnv* env, jobject thiz);
void JNICALL fis_close_hook(JNIEnv* env, jobject thiz);

#endif