#include "utils.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

jvmtiEnv* jvmti = NULL;
static const jlong TAG = 1;

void tag(jobject obj) {
    if (obj && jvmti) {
        (*jvmti)->SetTag(jvmti, obj, TAG);
    }
}

int has_tag(jobject obj) {
    jlong tag = 0;
    if (obj && jvmti) {
        (*jvmti)->GetTag(jvmti, obj, &tag);
    }
    return tag == 1;
}

int is_config_path(const char* path) {
    char* extString = strrchr(path, '.');
    if (extString) {
        return strcmp(extString, ".yml") == 0 || strcmp(extString, ".yaml") == 0 || strcmp(extString, ".json") == 0 || strcmp(extString, ".txt") == 0 || strcmp(extString, ".properties") == 0;
    }
    return 0;
}

char* substitute(const char* value, int dollar_sign_matched_index, size_t i, size_t env_len, const char *data) {
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