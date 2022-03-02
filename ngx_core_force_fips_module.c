/*
 * This derived work is copyrighted and licensed under the Apache License 2.0.
 * The license and attribution for the original work are as follows:
 *
 * Copyright (C) Owen Garrett
 *
 * License: Apache2
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/crypto.h>

typedef enum {
    UNKNOWN,
    DISABLED,
    ENABLED
} fips_state_t;

static fips_state_t fips_state = UNKNOWN;


static ngx_int_t ngx_force_fips(ngx_cycle_t *cycle);

static ngx_core_module_t ngx_force_fips_module_ctx = {
    ngx_string("force_fips"),
    NULL,
    NULL
};


ngx_module_t ngx_force_fips_module = {
    NGX_MODULE_V1,
    &ngx_force_fips_module_ctx,            /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_force_fips,                        /* init module */
    ngx_force_fips,                        /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_force_fips(ngx_cycle_t *cycle)
{
    int mode = FIPS_mode();

    //ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "Checking FIPS mode: %d, %d", fips_state, mode);

    // First time we run this check, at init master
    if( fips_state == UNKNOWN ) {
        if( mode == 0 ) {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "OpenSSL FIPS Mode is not yet enabled");

            mode = FIPS_mode_set(1);

            if (mode == 1) {
                ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "OpenSSL FIPS Mode is now enabled");
                fips_state = ENABLED;
            } else {
                fips_state = DISABLED;
            }
        } else {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "OpenSSL FIPS Mode is already enabled");
            fips_state = ENABLED;
        }
        return NGX_OK;
    }

    // Subsequent checks, at init worker
    // These checks are probably not necessary, as it should not be possible to switch the 
    // FIPS state once OpenSSL has been initialized in master, but are included out of 
    // caution

    if( fips_state == DISABLED ) {
        ngx_log_abort( 0, "EMERG: OpenSSL FIPS mode was not successfully enabled at startup" );
        return NGX_ERROR;
    }

    if( fips_state == ENABLED && mode == 0 ) {
        ngx_log_abort( 0, "EMERG: OpenSSL FIPS mode was enabled at startup, but is unexpectedly disabled" );
        return NGX_ERROR;
    }

    return NGX_OK;
}
