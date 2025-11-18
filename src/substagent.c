#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <jvmti.h>
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"
#include "build_info.h"

static jvmtiEnv* jvmti = NULL;

typedef void (JNICALL *open0_t)(JNIEnv*, jobject, jstring);
typedef jint (JNICALL *readBytes_t)(JNIEnv*, jobject, jbyteArray, jint, jint);
typedef jint (JNICALL *read0_t)(JNIEnv*, jobject);
typedef jlong (JNICALL *length0_t)(JNIEnv*, jobject);
typedef jlong (JNICALL *position0_t)(JNIEnv*, jobject);
typedef jlong (JNICALL *skip0_t)(JNIEnv*, jobject, jlong);
typedef jint (JNICALL *available0_t)(JNIEnv*, jobject);
typedef void (JNICALL *close_t)(JNIEnv*, jobject);
static readBytes_t real_readBytes = NULL;
static open0_t real_open0 = NULL;
static read0_t real_read0 = NULL;
static length0_t real_length0 = NULL;
static position0_t real_position0 = NULL;
static skip0_t real_skip0 = NULL;
static available0_t real_available0 = NULL;
static close_t real_close = NULL;

struct file_data {
    char* data;
    size_t index;
    size_t length;
    int freed;
};

struct file{
    jint key;
    struct file_data value;
} *files_map = NULL;

static const jlong TAG = 1;

static void tag(jobject obj) {
    if (obj && jvmti) {
        (*jvmti)->SetTag(jvmti, obj, TAG);
    }
}

static int has_tag(jobject obj) {
    jlong tag = 0;
    if (obj && jvmti) {
        (*jvmti)->GetTag(jvmti, obj, &tag);
    }
    return tag == 1;
}

static int is_config_path(const char* path) {
    char* extString = strrchr(path, '.');
    if (extString) {
        return strcmp(extString, ".yml") == 0 || strcmp(extString, ".yaml") == 0 || strcmp(extString, ".json") == 0 || strcmp(extString, ".txt") == 0 || strcmp(extString, ".properties") == 0;
    }
    return 0;
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) < (b) ? (b) : (a))

static void substitute(const char* value, size_t value_len, int dollar_sign_matched_index, size_t i, ssize_t len_diff, jsize ba_length, signed char* arr, jsize* used_bytes, signed char* exceeded, size_t* exceeded_len) {
    signed char before[dollar_sign_matched_index];
    size_t after_len = MAX(ba_length - (ssize_t)i - len_diff, 0);
    signed char after[after_len];
    memcpy(before, arr, dollar_sign_matched_index);
    memcpy(after, arr+i, after_len);

    signed char result[ba_length];
    memcpy(result, before, dollar_sign_matched_index);
    memcpy(result + dollar_sign_matched_index, value, value_len);
    memcpy(result + dollar_sign_matched_index + value_len, after, after_len);


    if (len_diff < 0) {
        // len_diff is negative so +- which equates to -
        *used_bytes += len_diff;
    } else if (len_diff > 0) {
        ssize_t clamped_free_bytes = MAX(ba_length - *used_bytes, 0);
        size_t already_copied_bytes = 0;
        if (clamped_free_bytes > 0) {
            already_copied_bytes = MIN(len_diff, clamped_free_bytes);
            *used_bytes += already_copied_bytes;
        }
        size_t new_exceeded_len = *exceeded_len + len_diff - already_copied_bytes;
        exceeded = realloc(exceeded, new_exceeded_len);
        memcpy(exceeded, exceeded, *exceeded_len);
        memcpy(exceeded+*exceeded_len, arr + (ba_length - len_diff) + already_copied_bytes, len_diff - already_copied_bytes);
        *exceeded_len = new_exceeded_len;
    }

    memcpy(arr, result, ba_length);
}

static char* new_substitute(const char* value, int dollar_sign_matched_index, size_t i, size_t env_len, const char *data) {
    size_t value_len = strlen(value);
    ssize_t len_diff = value_len - env_len;

    size_t data_len = strlen(data);
    size_t new_len = data_len+len_diff;
    char* new_data = malloc(new_len + 1);
    size_t after_len = new_len - dollar_sign_matched_index - value_len;
    memcpy(new_data, data, dollar_sign_matched_index);
    memcpy(new_data+dollar_sign_matched_index, value, value_len);
    memcpy(new_data+dollar_sign_matched_index+value_len, data+i, after_len);
    assert(dollar_sign_matched_index+value_len+after_len == new_len);
    new_data[new_len] = '\0';
    return new_data;
}

static jint JNICALL readBytes_hook(JNIEnv* env, jobject thiz, jbyteArray buf, jint off, jint len) {
    if (!has_tag(thiz)) {
        return real_readBytes(env, thiz, buf, off, len);
    }

    jclass class = (*env)->GetObjectClass(env, thiz);
    jmethodID hash_code_method = (*env)->GetMethodID(env, class, "hashCode", "()I");

    jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

    struct file *file = hmgetp(files_map, hash);
    if (file->key != hash || file->value.freed) {
        return -1;
    }

    struct file_data *fd = &file->value;
    jsize ba_length = (*env)->GetArrayLength(env, buf);
    jbyte *ba = (*env)->GetByteArrayElements(env, buf, JNI_FALSE);

    size_t remaining = fd->length - fd->index;

    jsize len_want_to_read = MIN((ba_length - off), len);
    jsize len_to_read = MIN(len_want_to_read, (jsize)remaining);
    if (len_to_read < 0) {
        (*env)->ReleaseByteArrayElements(env, buf, ba, 0);
        return -1;
    }
    memcpy(ba + off, fd->data + fd->index, len_to_read);

    (*env)->ReleaseByteArrayElements(env, buf, ba, 0);

    fd->index += len_to_read;
    if (fd->index == fd->length) {
        free(fd->data);
        fd->freed = 1;
    }
    return len_to_read;
}

static void JNICALL open0_hook(JNIEnv* env, jobject thiz, jstring jpath) {
    if (has_tag(thiz)) {
        return;
    }

    const char* path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (!path || !is_config_path(path)) {
        real_open0(env, thiz, jpath);
        return;
    }
    tag(thiz);

    jclass class = (*env)->GetObjectClass(env, thiz);
    jmethodID hash_code_method = (*env)->GetMethodID(env, class, "hashCode", "()I");
    jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

    FILE *file = fopen(path, "rb");
    if (!file) {
        jclass fileNotFoundException = (*env)->FindClass(env, "java/io/FileNotFoundException");
        (*env)->ThrowNew(env, fileNotFoundException, path);
        return;
    }
    fseek(file, 0, SEEK_END);
    size_t fsize = ftell(file);
    if (fsize == 0) {
        real_open0(env, thiz, jpath);
        return;
    }
    fseek(file, 0, SEEK_SET);

    char *file_data = malloc(fsize + 1);
    fread(file_data, fsize, 1, file);
    file_data[fsize] = '\0';

    int dollar_sign_matched_index = -1;
    char env_var[4096];
    env_var[0] = '\0';
    for (size_t i = 0; i < fsize; i++) {
        char c = file_data[i];
        if (dollar_sign_matched_index != -1) {
            if ((c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c == 95) {
                size_t len = strlen(env_var);
                env_var[len] = c;
                env_var[len + 1] = '\0';
            } else {
                if (strlen(env_var) == 0) continue;
                char* value = getenv(env_var);
                if (!value) {
                    dollar_sign_matched_index = -1;
                    env_var[0] = '\0';
                    continue;
                }

                size_t env_len = i - dollar_sign_matched_index;

                char* new_data = new_substitute(value, dollar_sign_matched_index, i, env_len, file_data);
                free(file_data);
                file_data = new_data;

                dollar_sign_matched_index = -1;
                env_var[0] = '\0';
                continue;
            }
        } else {
            if (c == '$') {
                dollar_sign_matched_index = i;
            }
        }
    }
    if (dollar_sign_matched_index != -1) {
        if (strlen(env_var) != 0) {
            char* value = getenv(env_var);
            if (value) {
                size_t env_len = fsize - dollar_sign_matched_index;

                char* new_data = new_substitute(value, dollar_sign_matched_index, fsize, env_len, file_data);
                free(file_data);
                file_data = new_data;
            }
        }
    }

    size_t fd_len = strlen(file_data);

    struct file_data fd;
    fd.data = file_data;
    fd.length = fd_len;
    fd.index = 0;
    fd.freed = 0;
    hmput(files_map, hash, fd);
    (*env)->ReleaseStringUTFChars(env, jpath, path);
}

static jint JNICALL read0_hook(JNIEnv* env, jobject thiz) {
    if (!has_tag(thiz)) {
        return real_read0(env, thiz);
    }

    jclass class = (*env)->GetObjectClass(env, thiz);
    jmethodID hash_code_method = (*env)->GetMethodID(env, class, "hashCode", "()I");

    jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

    struct file *file = hmgetp(files_map, hash);
    if (file->key != hash || file->value.freed) {
        return -1;
    }

    struct file_data *fd = &file->value;
    char read_byte = fd->data[fd->index++];
    if (fd->data[fd->index] == '\0') {
        free(fd->data);
        fd->freed = 1;
    }
    return read_byte;
}

static jlong JNICALL length0_hook(JNIEnv* env, jobject thiz) {
    if (!has_tag(thiz)) {
        return real_length0(env, thiz);
    }

    jclass class = (*env)->GetObjectClass(env, thiz);
    jmethodID hash_code_method = (*env)->GetMethodID(env, class, "hashCode", "()I");

    jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

    struct file *file = hmgetp(files_map, hash);
    if (file->key != hash) {
        return -1;
    }

    return file->value.length;
}

static jlong JNICALL position0_hook(JNIEnv* env, jobject thiz) {
    if (!has_tag(thiz)) {
        return real_length0(env, thiz);
    }

    jclass class = (*env)->GetObjectClass(env, thiz);
    jmethodID hash_code_method = (*env)->GetMethodID(env, class, "hashCode", "()I");

    jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

    struct file *file = hmgetp(files_map, hash);
    if (file->key != hash) {
        return -1;
    }

    return file->value.index;
}

static jlong JNICALL skip0_hook(JNIEnv* env, jobject thiz, jlong n) {
    if (!has_tag(thiz)) {
        return real_skip0(env, thiz, n);
    }

    jclass class = (*env)->GetObjectClass(env, thiz);
    jmethodID hash_code_method = (*env)->GetMethodID(env, class, "hashCode", "()I");

    jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

    struct file *file = hmgetp(files_map, hash);
    if (file->key != hash) {
        return 0;
    }

    struct file_data *fd = &file->value;

    size_t remaining = fd->length - fd->index;
    size_t skip = MIN(remaining, n);
    fd->index += skip;
    if (skip == remaining) {
        free(fd->data);
        fd->freed = 1;
        return skip;
    }

    return skip;
}

static jint JNICALL available0_hook(JNIEnv* env, jobject thiz) {
    if (!has_tag(thiz)) {
        return real_available0(env, thiz);
    }

    jclass class = (*env)->GetObjectClass(env, thiz);
    jmethodID hash_code_method = (*env)->GetMethodID(env, class, "hashCode", "()I");

    jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

    struct file *file = hmgetp(files_map, hash);
    if (file->key != hash) {
        return 0;
    }

    struct file_data *fd = &file->value;
    return fd->length - fd->index;
}

static void JNICALL close_hook(JNIEnv* env, jobject thiz) {
    if (!has_tag(thiz)) {
        return real_close(env, thiz);
    }

    jclass class = (*env)->GetObjectClass(env, thiz);
    jmethodID hash_code_method = (*env)->GetMethodID(env, class, "hashCode", "()I");

    jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

    struct file *file = hmgetp(files_map, hash);
    if (file->key != hash) {
        return;
    }

    free(file->value.data);
    file->value.freed = 1;
    return;
}

static void dealloc(jvmtiEnv* jvmti, char* p) {
    if (p != NULL) {
        unsigned char* up = (unsigned char*)p;
        (*jvmti)->Deallocate(jvmti, up);
    }
}

static void JNICALL onNativeMethodBind(jvmtiEnv* jvmti_env, JNIEnv* env, jthread thread, jmethodID method, void* address, void** new_address_ptr) {
    char* mname = NULL;
    char* msig  = NULL;
    char* csig  = NULL;
    char* gsig  = NULL;

    jclass decl;
    (*jvmti_env)->GetMethodDeclaringClass(jvmti_env, method, &decl);
    (*jvmti_env)->GetClassSignature(jvmti_env, decl, &csig, &gsig);
    (*jvmti_env)->GetMethodName(jvmti_env, method, &mname, &msig, NULL);

    if (csig && strcmp(csig, "Ljava/io/FileInputStream;") == 0 && mname && msig) {
        // private native void open0(String name)
        if (strcmp(mname, "open0") == 0 && strcmp(msig, "(Ljava/lang/String;)V") == 0) {
            real_open0 = (open0_t)address;
            *new_address_ptr = (void*)&open0_hook;
        // private native int readBytes(byte b[], int off, int len)
        } else if (strcmp(mname, "readBytes") == 0 && strcmp(msig, "([BII)I") == 0) {
            real_readBytes = (readBytes_t)address;
            *new_address_ptr = (void*)&readBytes_hook;
        // private native int read0
        } else if (strcmp(mname, "read0") == 0 && strcmp(msig, "()I") == 0) {
            real_read0 = (read0_t)address;
            *new_address_ptr = (void*)&read0_hook;
        // private native long length0()
        } else if (strcmp(mname, "length0") == 0 && strcmp(msig, "()J") == 0) {
            real_length0 = (length0_t)address;
            *new_address_ptr = (void*)&length0_hook;
        // private native long position0()
        } else if (strcmp(mname, "position0") == 0 && strcmp(msig, "()J") == 0) {
            real_position0 = (position0_t)address;
            *new_address_ptr = (void*)&position0_hook;
        // private native long skip0(long n)
        } else if (strcmp(mname, "skip0") == 0 && strcmp(msig, "(J)J") == 0) {
            real_skip0 = (skip0_t)address;
            *new_address_ptr = (void*)&skip0_hook;
        // private native int available0()
        } else if (strcmp(mname, "available0") == 0 && strcmp(msig, "()I") == 0) {
            real_available0 = (available0_t)address;
            *new_address_ptr = (void*)&available0_hook;
        // public void close()
        } else if (strcmp(mname, "close") == 0 && strcmp(msig, "()V") == 0) {
            real_close = (close_t)address;
            *new_address_ptr = (void*)&close_hook;
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
    } else {
        if (errno != ENOENT) {
            perror("[SubstAgent] fopen failed");
            exit(EXIT_FAILURE);
        }
    }

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
