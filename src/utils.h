#ifndef UTILS_H
#define UTILS_H

#include <jvmti.h>
#include <jni.h>

extern jvmtiEnv* jvmti;

void tag(jobject obj);
int has_tag(jobject obj);
int is_config_path(const char* path);
char* substitute(const char* value, int dollar_sign_matched_index, size_t i, size_t env_len, const char *data);
void parse_file(char **data_ptr, size_t fsize);

struct file_data {
    char* data;
    size_t index;
    size_t length;
    int freed;
};

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) < (b) ? (b) : (a))

#endif