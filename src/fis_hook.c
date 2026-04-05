#include "fis_hook.h"
#include "utils.h"
#include <stdio.h>
#include <sys/stat.h>
#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

fis_readBytes_t fis_real_readBytes = NULL;
fis_open0_t fis_real_open0 = NULL;
fis_read0_t fis_real_read0 = NULL;
fis_length0_t fis_real_length0 = NULL;
fis_position0_t fis_real_position0 = NULL;
fis_skip0_t fis_real_skip0 = NULL;
fis_available0_t fis_real_available0 = NULL;
fis_close_t fis_real_close = NULL;

struct fis_file_data {
  char *data;
  size_t index;
  size_t length;
};

struct file {
  jint key;
  struct fis_file_data value;
} *fis_files_map = NULL;

jint JNICALL fis_readBytes_hook(JNIEnv *env, jobject thiz, jbyteArray buf,
                                jint off, jint len) {
  if (!has_tag(thiz)) {
    return fis_real_readBytes(env, thiz, buf, off, len);
  }

  jclass class = (*env)->GetObjectClass(env, thiz);
  jmethodID hash_code_method =
      (*env)->GetMethodID(env, class, "hashCode", "()I");

  jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

  struct file *file = hmgetp_null(fis_files_map, hash);
  if (file == NULL || file->value.data == NULL) {
    return -1;
  }

  struct fis_file_data *fd = &file->value;
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
    fd->data = NULL;
  }

  return len_to_read;
}

void JNICALL fis_open0_hook(JNIEnv *env, jobject thiz, jstring jpath) {
  if (has_tag(thiz)) {
    return;
  }

  const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
  if (!path || !is_config_path(path)) {
    fis_real_open0(env, thiz, jpath);
    return;
  }
  tag(thiz);

  jclass class = (*env)->GetObjectClass(env, thiz);
  jmethodID hash_code_method =
      (*env)->GetMethodID(env, class, "hashCode", "()I");
  jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

  FILE *file = fopen(path, "rb");
  if (!file) {
    jclass fileNotFoundException =
        (*env)->FindClass(env, "java/io/FileNotFoundException");
    (*env)->ThrowNew(env, fileNotFoundException, path);
    return;
  }

  struct stat st;
  if (fstat(fileno(file), &st) != 0) {
    jclass fileNotFoundException =
        (*env)->FindClass(env, "java/io/FileNotFoundException");
    (*env)->ThrowNew(env, fileNotFoundException, path);
    return;
  }
  size_t fsize = st.st_size;
  if (fsize == 0) {
    fclose(file);
    return;
  }

  char *data = malloc(fsize + 1);
  fread(data, fsize, 1, file);
  fclose(file);
  data[fsize] = '\0';

  parse_file(&data, fsize, path);

  size_t fd_len = strlen(data);

  struct fis_file_data file_data;
  file_data.data = data;
  file_data.length = fd_len;
  file_data.index = 0;
  hmput(fis_files_map, hash, file_data);
  (*env)->ReleaseStringUTFChars(env, jpath, path);
}

jint JNICALL fis_read0_hook(JNIEnv *env, jobject thiz) {
  if (!has_tag(thiz)) {
    return fis_real_read0(env, thiz);
  }

  jclass class = (*env)->GetObjectClass(env, thiz);
  jmethodID hash_code_method =
      (*env)->GetMethodID(env, class, "hashCode", "()I");

  jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

  struct file *file = hmgetp_null(fis_files_map, hash);
  if (file == NULL || file->value.data == NULL) {
    return -1;
  }

  struct fis_file_data *fd = &file->value;
  char read_byte = fd->data[fd->index++];
  if (fd->data[fd->index] == '\0') {
    free(fd->data);
    fd->data = NULL;
  }
  return read_byte;
}

jlong JNICALL fis_length0_hook(JNIEnv *env, jobject thiz) {
  if (!has_tag(thiz)) {
    return fis_real_length0(env, thiz);
  }

  jclass class = (*env)->GetObjectClass(env, thiz);
  jmethodID hash_code_method =
      (*env)->GetMethodID(env, class, "hashCode", "()I");

  jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

  struct file *file = hmgetp_null(fis_files_map, hash);
  if (file == NULL) {
    return -1;
  }

  return file->value.length;
}

jlong JNICALL fis_position0_hook(JNIEnv *env, jobject thiz) {
  if (!has_tag(thiz)) {
    return fis_real_length0(env, thiz);
  }

  jclass class = (*env)->GetObjectClass(env, thiz);
  jmethodID hash_code_method =
      (*env)->GetMethodID(env, class, "hashCode", "()I");

  jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

  struct file *file = hmgetp_null(fis_files_map, hash);
  if (file == NULL) {
    return -1;
  }

  return file->value.index;
}

jlong JNICALL fis_skip0_hook(JNIEnv *env, jobject thiz, jlong n) {
  if (!has_tag(thiz)) {
    return fis_real_skip0(env, thiz, n);
  }

  jclass class = (*env)->GetObjectClass(env, thiz);
  jmethodID hash_code_method =
      (*env)->GetMethodID(env, class, "hashCode", "()I");

  jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

  struct file *file = hmgetp_null(fis_files_map, hash);
  if (file == NULL) {
    return 0;
  }

  struct fis_file_data *fd = &file->value;

  size_t remaining = fd->length - fd->index;
  size_t skip = MIN(remaining, n);
  fd->index += skip;
  if (skip == remaining) {
    free(fd->data);
    fd->data = NULL;
    return skip;
  }

  return skip;
}

jint JNICALL fis_available0_hook(JNIEnv *env, jobject thiz) {
  if (!has_tag(thiz)) {
    return fis_real_available0(env, thiz);
  }

  jclass class = (*env)->GetObjectClass(env, thiz);
  jmethodID hash_code_method =
      (*env)->GetMethodID(env, class, "hashCode", "()I");

  jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

  struct file *file = hmgetp_null(fis_files_map, hash);
  if (file == NULL) {
    return 0;
  }

  struct fis_file_data *fd = &file->value;
  return fd->length - fd->index;
}

void JNICALL fis_close_hook(JNIEnv *env, jobject thiz) {
  if (!has_tag(thiz)) {
    return fis_real_close(env, thiz);
  }

  jclass class = (*env)->GetObjectClass(env, thiz);
  jmethodID hash_code_method =
      (*env)->GetMethodID(env, class, "hashCode", "()I");

  jint hash = (*env)->CallIntMethod(env, thiz, hash_code_method);

  struct file *file = hmgetp_null(fis_files_map, hash);
  if (file == NULL) {
    return;
  }

  free(file->value.data);
  file->value.data = NULL;
  return;
}