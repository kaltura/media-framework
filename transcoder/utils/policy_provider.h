#pragma once

#include "config.h"
struct policy_provider_s;
typedef int (*error_handler_t)(struct policy_provider_s *ctx,int error);

typedef struct policy_provider_s {
    void *ctx;
    error_handler_t handle_error;
} policy_provider_s, *policy_provider_t;

int init_policy_provider(policy_provider_t provider,json_value_t* config);
void free_policy_provider(policy_provider_t provider);
