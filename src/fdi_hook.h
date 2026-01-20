#ifndef FDI_HOOK_H
#define FDI_HOOK_H

#include <jvmti.h>
#include <jni.h>

typedef jint (JNICALL *und_open0_t)(JNIEnv*, jobject, jlong, jint, jint);
extern und_open0_t und_real_open0;
typedef jint (JNICALL *und_close0_t)(JNIEnv*, jobject, jint);
extern und_close0_t und_real_close0;

typedef jint (JNICALL *fdi_read0_t)(JNIEnv*, jobject, jobject, jlong, jint);
extern fdi_read0_t fdi_real_read0;

jint JNICALL und_open0_hook(JNIEnv*, jobject, jlong, jint, jint);
void JNICALL und_close0_hook(JNIEnv*, jobject, jint);

jint JNICALL fdi_read0_hook(JNIEnv*, jobject, jobject, jlong, jint);

#endif