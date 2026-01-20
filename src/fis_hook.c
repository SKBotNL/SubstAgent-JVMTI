#include "fis_hook.h"
#include "utils.h"
#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

readBytes_t fis_real_readBytes = NULL;
open0_t fis_real_open0 = NULL;
read0_t fis_real_read0 = NULL;
length0_t fis_real_length0 = NULL;
position0_t fis_real_position0 = NULL;
skip0_t fis_real_skip0 = NULL;
available0_t fis_real_available0 = NULL;
close_t fis_real_close = NULL;

struct file{
    jint key;
    struct file_data value;
} *files_map = NULL;

jint JNICALL fis_readBytes_hook(JNIEnv* env, jobject thiz, jbyteArray buf, jint off, jint len) {
    if (!has_tag(thiz)) {
        return fis_real_readBytes(env, thiz, buf, off, len);
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

void JNICALL fis_open0_hook(JNIEnv* env, jobject thiz, jstring jpath) {
    if (has_tag(thiz)) {
        return;
    }

    const char* path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (!path || !is_config_path(path)) {
        fis_real_open0(env, thiz, jpath);
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
        fis_real_open0(env, thiz, jpath);
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

                char* new_data = substitute(value, dollar_sign_matched_index, i, env_len, file_data);
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

                char* new_data = substitute(value, dollar_sign_matched_index, fsize, env_len, file_data);
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

jint JNICALL fis_read0_hook(JNIEnv* env, jobject thiz) {
    if (!has_tag(thiz)) {
        return fis_real_read0(env, thiz);
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

jlong JNICALL fis_length0_hook(JNIEnv* env, jobject thiz) {
    if (!has_tag(thiz)) {
        return fis_real_length0(env, thiz);
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

jlong JNICALL fis_position0_hook(JNIEnv* env, jobject thiz) {
    if (!has_tag(thiz)) {
        return fis_real_length0(env, thiz);
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

jlong JNICALL fis_skip0_hook(JNIEnv* env, jobject thiz, jlong n) {
    if (!has_tag(thiz)) {
        return fis_real_skip0(env, thiz, n);
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

jint JNICALL fis_available0_hook(JNIEnv* env, jobject thiz) {
    if (!has_tag(thiz)) {
        return fis_real_available0(env, thiz);
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

void JNICALL fis_close_hook(JNIEnv* env, jobject thiz) {
    if (!has_tag(thiz)) {
        return fis_real_close(env, thiz);
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