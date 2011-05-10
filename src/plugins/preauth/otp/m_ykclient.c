/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2011 NORDUnet A/S.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Red Hat, Inc., nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* FAST OTP plugin method for (legacy) Yubikey OTP validation.  */

#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <ykclient.h>

#include "otp.h"
#include "m_ykclient.h"

#define YUBIKEY_URL_TEMPLATE "otp_ykclient_url_template"
#define YUBIKEY_CLIENT_ID "otp_ykclient_client_id"

#define YUBIKEY_ID_LENGTH 12
#define YUBIKEY_TOKEN_LENGTH 44

struct otp_ykclient_ctx {
    ykclient_t *yk_ctx;
    char *url_template;
};

static void
server_fini(void *method_context)
{
    struct otp_ykclient_ctx *ctx = method_context;
    assert(ctx);

    ykclient_done(&ctx->yk_ctx);
    free(ctx);
}

static int
verify_otp(const struct otp_server_ctx *otp_ctx, const char *pw)
{
    struct otp_ykclient_ctx *ctx = OTP_METHOD_CONTEXT(otp_ctx);
    int ret = -1;
    assert(otp_ctx != NULL);

    if (pw == NULL) {
        SERVER_DEBUG("[ykclient] OTP is missing.");
        return EINVAL;
    }

    /* TODO: Use blob in ctx->otp_context->blob to get hold of
       whatever is needed for doing the ykclient request.  */

    ret = ykclient_request (ctx->yk_ctx, pw);
    if (ret == YKCLIENT_OK) {
        ret = 0;
    }

    return ret;
}

int
otp_ykclient_server_init(struct otp_server_ctx *otp_ctx,
                         get_config_func_t get_config,
                         search_db_func_t search_db,
                         struct otp_method_ftable **ftable,
                         void **method_context)
{
    int retval = -1;
    struct otp_ykclient_ctx *ctx = NULL;
    struct otp_method_ftable *ft = NULL;
    char *client_id_str = NULL;
    int client_id = 0;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        retval = ENOMEM;
        goto errout;
    }
    ft = calloc(1, sizeof(*ft));
    if (ft == NULL) {
        retval = ENOMEM;
        goto errout;
    }
    ft->server_fini = server_fini;
    ft->server_verify = verify_otp;

    /* Initialize ykclient.  */
    retval = ykclient_init(&ctx->yk_ctx);
    if (retval != YKCLIENT_OK) {
        SERVER_DEBUG("[ykclient] ykclient_init failed.\n");
        retval += 200;
        assert(ctx->yk_ctx == NULL);
        goto errout;
    }
    assert(ctx->yk_ctx != NULL);

    /* Set URL.  */
    ctx->url_template = get_config(otp_ctx, NULL, YUBIKEY_URL_TEMPLATE);
    if (ctx->url_template != NULL) {
        ykclient_set_url_template(ctx->yk_ctx, ctx->url_template);
    }
    else {
        SERVER_DEBUG("[ykclient] Failed to retrive URL template.");
        retval = ENOENT;
        goto errout;
    }

    /* Set client id.  We probably want to move this to verify_otp()
       where the binary blob is available.  */
    client_id_str = get_config(otp_ctx, NULL, YUBIKEY_CLIENT_ID);
    if (client_id_str != NULL) {
        errno = 0;
        client_id = (int) strtol(client_id_str, NULL, 0);
        free(client_id_str);
        if (errno != 0) {
            client_id = 0;
        }
    }
    if (client_id != 0) {
        /* TODO: Set key too.  */
        ykclient_set_client(ctx->yk_ctx, client_id, 0, NULL);
    }
    else {
        SERVER_DEBUG("[ykclient] Invalid client id in config: [%s]\n",
                     client_id_str);
        retval = EINVAL;
        goto errout;
    }

    *ftable = ft;
    *method_context = ctx;
    return 0;

 errout:
    if (ctx->yk_ctx != NULL) {
        ykclient_done(&ctx->yk_ctx);
    }
    if (ft != NULL) {
        free(ft);
    }
    if (ctx != NULL) {
        free(ctx);
    }
    return retval;
}
