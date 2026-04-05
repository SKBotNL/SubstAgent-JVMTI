#ifndef FIS_HOOK_H
#define FIS_HOOK_H

#include <jvmti.h>

typedef void(JNICALL *fis_open0_t)(JNIEnv *, jobject, jstring);
typedef jint(JNICALL *fis_readBytes_t)(JNIEnv *, jobject, jbyteArray, jint,
                                       jint);
typedef jint(JNICALL *fis_read0_t)(JNIEnv *, jobject);
typedef jlong(JNICALL *fis_length0_t)(JNIEnv *, jobject);
typedef jlong(JNICALL *fis_position0_t)(JNIEnv *, jobject);
typedef jlong(JNICALL *fis_skip0_t)(JNIEnv *, jobject, jlong);
typedef jint(JNICALL *fis_available0_t)(JNIEnv *, jobject);
typedef void(JNICALL *fis_close_t)(JNIEnv *, jobject);
extern fis_readBytes_t fis_real_readBytes;
extern fis_open0_t fis_real_open0;
extern fis_read0_t fis_real_read0;
extern fis_length0_t fis_real_length0;
extern fis_position0_t fis_real_position0;
extern fis_skip0_t fis_real_skip0;
extern fis_available0_t fis_real_available0;
extern fis_close_t fis_real_close;

jint JNICALL fis_readBytes_hook(JNIEnv *env, jobject thiz, jbyteArray buf,
                                jint off, jint len);
void JNICALL fis_open0_hook(JNIEnv *env, jobject thiz, jstring jpath);
jint JNICALL fis_read0_hook(JNIEnv *env, jobject thiz);
jlong JNICALL fis_length0_hook(JNIEnv *env, jobject thiz);
jlong JNICALL fis_position0_hook(JNIEnv *env, jobject thiz);
jlong JNICALL fis_skip0_hook(JNIEnv *env, jobject thiz, jlong n);
jint JNICALL fis_available0_hook(JNIEnv *env, jobject thiz);
void JNICALL fis_close_hook(JNIEnv *env, jobject thiz);

#endif