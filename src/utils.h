#ifndef UTILS_H
#define UTILS_H

#include <jvmti.h>

extern jvmtiEnv *jvmti;

void tag(jobject obj);
int has_tag(jobject obj);
int is_config_path(const char *path);
char *substitute(const char *value, int dollar_sign_matched_index, size_t i,
                 size_t value_len, size_t len_diff, const char *data);
void parse_file(char **data_ptr, size_t fsize, const char *filename);

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) < (b) ? (b) : (a))

#endif