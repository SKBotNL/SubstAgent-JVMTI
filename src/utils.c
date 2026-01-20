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

void parse_file(char **data_ptr, size_t fsize) {
    char *data = *data_ptr;
    int dollar_sign_matched_index = -1;
    char env_var[4096];
    env_var[0] = '\0';
    for (size_t i = 0; i < fsize; i++) {
        char c = data[i];
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

                char* new_data = substitute(value, dollar_sign_matched_index, i, env_len, data);
                free(data);
                data = new_data;
                *data_ptr = new_data;

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

                char* new_data = substitute(value, dollar_sign_matched_index, fsize, env_len, data);
                free(data);
                data = new_data;
                *data_ptr = new_data;
            }
        }
    }
}