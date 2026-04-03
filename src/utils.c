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

char* substitute(const char* value, int prefix_char_matched_index, size_t i, size_t env_len, const char *data) {
    size_t value_len = strlen(value);
    ssize_t len_diff = value_len - env_len;

    size_t data_len = strlen(data);
    size_t new_len = data_len+len_diff;
    char* new_data = malloc(new_len + 1);
    size_t after_len = new_len - prefix_char_matched_index - value_len;
    memcpy(new_data, data, prefix_char_matched_index);
    memcpy(new_data+prefix_char_matched_index, value, value_len);
    memcpy(new_data+prefix_char_matched_index+value_len, data+i, after_len);
    assert(prefix_char_matched_index+value_len+after_len == new_len);
    new_data[new_len] = '\0';
    return new_data;
}

void parse_file(char **data_ptr, size_t fsize, const char* filename) {
    char *data = *data_ptr;
    int line_count = 1;;
    int begin_env_index = -1;
    char env_var[4096];
    env_var[0] = '\0';
    for (size_t i = 0; i < fsize; i++) {
        char c = data[i];
        if (c == '\n') ++line_count;
        if (begin_env_index != -1) {
            if ((c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c == 95) {
                size_t len = strlen(env_var);
                env_var[len] = c;
                env_var[len + 1] = '\0';
            } else if (c == '}') {
                if (strlen(env_var) == 0) {
                    begin_env_index = -1;
                    env_var[0] = '\0';
                    continue;
                }
                char* value = getenv(env_var);
                if (!value) {
                    fprintf(stderr, "\033[0G\e[0;31m[SubstAgent] Failed to expand environment variable \"%s\" in file %s on line %d\e[0m\n", env_var, filename, line_count);
                    begin_env_index = -1;
                    env_var[0] = '\0';
                    continue;
                }

                // +1 for the closing }
                size_t after_closing_tag_index = i + 1;

                size_t env_len = after_closing_tag_index - begin_env_index;

                char* new_data = substitute(value, begin_env_index, after_closing_tag_index, env_len, data);
                free(data);
                data = new_data;
                *data_ptr = new_data;

                fprintf(stderr, "\033[0G[SubstAgent] Successfully expanded environment variable \"%s\" in file %s on line %d\n", env_var, filename, line_count);
                begin_env_index = -1;
                env_var[0] = '\0';
                continue;
            } else {
                fprintf(stderr, "\033[0G\e[0;31m[SubstAgent] Invalid environment variable in file %s on line %d\e[0m\n", filename, line_count);
                begin_env_index = -1;
                env_var[0] = '\0';
            }
        } else {
            if (c == '^') {
                if (data[i+1] == '{') {
                    begin_env_index = i;
                    i++;
                }
            }
        }
    }
}