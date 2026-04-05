#include "fdi_hook.h"
#include "stb_ds.h"
#include "utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>

und_open0_t und_real_open0 = NULL;
und_close0_t und_real_close0 = NULL;

fdi_read0_t fdi_real_read0 = NULL;

struct fdi_file_data {
  char *data;
  size_t index;
  size_t length;
  int freed;
  size_t inode;
  size_t device;
};

struct file {
  jint key;
  struct fdi_file_data value;
} *fdi_files_map = NULL;

jint JNICALL und_open0_hook(JNIEnv *env, jobject thiz, jlong path_address,
                            jint flags, jint mode) {
  jint fd = und_real_open0(env, thiz, path_address, flags, mode);
  const char *path = (const char *)(intptr_t)path_address;
  if (!path || !is_config_path(path)) {
    return fd;
  }

  struct stat st;
  if (fstat(fd, &st) != 0) {
    jclass fileNotFoundException =
        (*env)->FindClass(env, "java/io/FileNotFoundException");
    (*env)->ThrowNew(env, fileNotFoundException, path);
    return fd;
  }
  size_t fsize = st.st_size;

  FILE *file = fopen(path, "rb");
  if (!file) {
    jclass fileNotFoundException =
        (*env)->FindClass(env, "java/io/FileNotFoundException");
    (*env)->ThrowNew(env, fileNotFoundException, path);
    return fd;
  }

  char *data = malloc(fsize + 1);
  fread(data, fsize, 1, file);
  fclose(file);
  data[fsize] = '\0';

  parse_file(&data, fsize, path);

  size_t fd_len = strlen(data);

  struct fdi_file_data file_data;
  file_data.data = data;
  file_data.length = fd_len;
  file_data.index = 0;
  file_data.freed = 0;
  file_data.inode = st.st_ino;
  file_data.device = st.st_dev;
  hmput(fdi_files_map, fd, file_data);

  return fd;
}

void JNICALL und_close0_hook(JNIEnv *env, jobject thiz, jint fd) {
  struct file *file = hmgetp_null(fdi_files_map, fd);
  if (file != NULL) {
    free(file->value.data);
    file->value.data = NULL;
    hmdel(fdi_files_map, fd);
  }
}

jint JNICALL fdi_read0_hook(JNIEnv *env, jobject thiz, jobject fdObject,
                            jlong address, jint len) {
  jclass class = (*env)->GetObjectClass(env, fdObject);
  jfieldID fieldID = (*env)->GetFieldID(env, class, "fd", "I");
  jint fd = (*env)->GetIntField(env, fdObject, fieldID);

  struct file *file = hmgetp_null(fdi_files_map, fd);
  if (file == NULL) {
    return fdi_real_read0(env, thiz, fdObject, address, len);
  }

  struct fdi_file_data *file_data = &file->value;
  struct stat st;
  if (fstat(fd, &st) != 0) {
    hmdel(fdi_files_map, fd);
    return fdi_real_read0(env, thiz, fdObject, address, len);
  }

  // Check if it's still the same file
  if (st.st_ino != file_data->inode || st.st_dev != file_data->device) {
    hmdel(fdi_files_map, fd);
    return fdi_real_read0(env, thiz, fdObject, address, len);
  }

  if (file_data->freed) {
    return -1;
  }

  if (file_data->length == 0) {
    free(file_data->data);
    file_data->data = NULL;
    file_data->freed = 1;
    return -1;
  }

  int n = MIN(len, file_data->length - file_data->index);
  memcpy((void *)(intptr_t)address, file_data->data + file_data->index, n);

  if (n == file_data->length - file_data->index) {
    free(file_data->data);
    file_data->data = NULL;
    file_data->freed = 1;
  } else {
    file_data->index += n;
  }

  return n;
}