#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <jvmti.h>
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "build_info.h"
#include "fis_hook.h"
#include "utils.h"

static void JNICALL onNativeMethodBind(jvmtiEnv* jvmti_env, JNIEnv* env, jthread thread, jmethodID method, void* address, void** new_address_ptr) {
    char* mname = NULL;
    char* msig  = NULL;
    char* csig  = NULL;
    char* gsig  = NULL;

    jclass decl;
    (*jvmti_env)->GetMethodDeclaringClass(jvmti_env, method, &decl);
    (*jvmti_env)->GetClassSignature(jvmti_env, decl, &csig, &gsig);
    (*jvmti_env)->GetMethodName(jvmti_env, method, &mname, &msig, NULL);

    if (csig && mname && msig) {
        if (strcmp(csig, "Ljava/io/FileInputStream;") == 0) {
            // private native void open0(String name)
            if (strcmp(mname, "open0") == 0 && strcmp(msig, "(Ljava/lang/String;)V") == 0) {
                fis_real_open0 = (open0_t)address;
                *new_address_ptr = (void*)&fis_open0_hook;
            // private native int readBytes(byte b[], int off, int len)
            } else if (strcmp(mname, "readBytes") == 0 && strcmp(msig, "([BII)I") == 0) {
                fis_real_readBytes = (readBytes_t)address;
                *new_address_ptr = (void*)&fis_readBytes_hook;
            // private native int read0
            } else if (strcmp(mname, "read0") == 0 && strcmp(msig, "()I") == 0) {
                fis_real_read0 = (read0_t)address;
                *new_address_ptr = (void*)&fis_read0_hook;
            // private native long length0()
            } else if (strcmp(mname, "length0") == 0 && strcmp(msig, "()J") == 0) {
                fis_real_length0 = (length0_t)address;
                *new_address_ptr = (void*)&fis_length0_hook;
            // private native long position0()
            } else if (strcmp(mname, "position0") == 0 && strcmp(msig, "()J") == 0) {
                fis_real_position0 = (position0_t)address;
                *new_address_ptr = (void*)&fis_position0_hook;
            // private native long skip0(long n)
            } else if (strcmp(mname, "skip0") == 0 && strcmp(msig, "(J)J") == 0) {
                fis_real_skip0 = (skip0_t)address;
                *new_address_ptr = (void*)&fis_skip0_hook;
            // private native int available0()
            } else if (strcmp(mname, "available0") == 0 && strcmp(msig, "()I") == 0) {
                fis_real_available0 = (available0_t)address;
                *new_address_ptr = (void*)&fis_available0_hook;
            // public void close()
            } else if (strcmp(mname, "close") == 0 && strcmp(msig, "()V") == 0) {
                fis_real_close = (close_t)address;
                *new_address_ptr = (void*)&fis_close_hook;
            }
        }
    }

    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)mname);
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)msig);
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)csig);
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)gsig);
}

static jint init_jvmti(JavaVM* vm) {
    jint rc = (*vm)->GetEnv(vm, (void**)&jvmti, JVMTI_VERSION_1_2);
    if (rc != JNI_OK || jvmti == NULL) return JNI_ERR;

    jvmtiCapabilities caps;
    memset(&caps, 0, sizeof(caps));
    caps.can_generate_native_method_bind_events = 1;
    caps.can_tag_objects = 1;
    (*jvmti)->AddCapabilities(jvmti, &caps);

    jvmtiEventCallbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.NativeMethodBind = &onNativeMethodBind;
    (*jvmti)->SetEventCallbacks(jvmti, &callbacks, (jint)sizeof(callbacks));

    (*jvmti)->SetEventNotificationMode(jvmti, JVMTI_ENABLE, JVMTI_EVENT_NATIVE_METHOD_BIND, (jthread)NULL);

    FILE *env_file = fopen(".env", "r");
    if (env_file) {
        char* line = NULL;
        size_t len = 0;
        ssize_t n;
        while ((n = getline(&line, &len, env_file)) != -1) {
            if (n > 0 && line[n - 1] == '\n') {
                line[n - 1] = '\0';
            }
            if (line[0] == '#') {
                continue;
            }
            char *name = line;
            char *value = NULL;
            char *equal = strchr(line, '=');
            if (equal == NULL) {
                fprintf(stderr, "\e[0;31m[SubstAgent] Invalid line in .env: \"%s\"\e[0m\n", line);
                continue;
            }
            *equal = '\0';
            value = equal + 1;
            if (setenv(name, value, 0) != 0) {
                perror("setenv failed");
            }
        }
        free(line);
    } else {
        if (errno != ENOENT) {
            perror("[SubstAgent] fopen failed");
            exit(EXIT_FAILURE);
        }
    }
    fclose(env_file);

    fprintf(stderr, "[SubstAgent] Loaded version %s\n", GIT_HASH);

    return JNI_OK;
}

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM* vm, char* options, void* reserved) {
    return init_jvmti(vm);
}

JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM* vm, char* options, void* reserved) {
    return init_jvmti(vm);
}

JNIEXPORT void JNICALL Agent_OnUnload(JavaVM* vm) {}
