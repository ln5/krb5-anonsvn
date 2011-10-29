/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2011 NORDUnet A/S.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
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

/* FAST OTP plugin method for http(s) basic authentication.  */

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <curl/curl.h>

#include "otp.h"
#include "m_basicauth.h"

#define URL_TEMPLATE "otp_basicauth_url_template"

struct otp_basicauth_ctx {
#ifdef DEBUG
#define MAGIC_OTP_BASICAUTH_CTX 0xdead4711
    unsigned int magic;
#endif
    struct otp_server_ctx *otp_context;
    get_config_func_t get_config;

    CURL *curlh;
    char *url;
};

static void
server_fini(void *method_context)
{
    struct otp_basicauth_ctx *ctx = method_context;
    assert(ctx);
#ifdef DEBUG
    assert(ctx->magic == MAGIC_OTP_BASICAUTH_CTX);
#endif

    curl_easy_cleanup(ctx->curlh);
    curl_global_cleanup();
    free(ctx->url);
    free(ctx);
}

#if !defined DEBUG
static size_t
curl_wfunc(void *ptr, size_t size, size_t nmemb, void *stream)
{
    return size * nmemb;
}
#endif  /* !DEBUG */

static int
verify_otp(const struct otp_req_ctx *req_ctx, const char *pw)
{
    struct otp_basicauth_ctx *ctx = NULL;
    char *username = NULL;
    CURLcode cret = 0;
    long respcode = 0;
    char curl_errbuf[CURL_ERROR_SIZE];

    ctx = OTP_METHOD_CONTEXT(req_ctx);
    assert(ctx != NULL);
#ifdef DEBUG
    assert(ctx->magic == MAGIC_OTP_BASICAUTH_CTX);
#endif

    if (pw == NULL) {
        SERVER_DEBUG(EINVAL, "[basicauth] OTP is missing.");
        return EINVAL;
    }

    /* Blob contains username.  */
    if (req_ctx->blob == NULL) {
        SERVER_DEBUG(EINVAL, "[basicauth] Blob is missing.");
        return EINVAL;
    }
    username = req_ctx->blob;

    if (ctx->url == NULL) {
        SERVER_DEBUG(EINVAL,
                     "[basicauth] Missing otp_url_template in krb5.conf.");
        return EINVAL;
    }

    /* Set curl options.  */
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_URL, ctx->url);
    if (cret != CURLE_OK) {
        SERVER_DEBUG(cret, "%s:%d: curl error.", __func__, __LINE__);
        return 200 + cret;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    if (cret != CURLE_OK) {
        SERVER_DEBUG(cret, "%s:%d: curl error.", __func__, __LINE__);
        return 200 + cret;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_USERNAME, username);
    if (cret != CURLE_OK) {
        SERVER_DEBUG(cret, "%s:%d: curl error.", __func__, __LINE__);
        return 200 + cret;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_PASSWORD, pw);
    if (cret != CURLE_OK) {
        SERVER_DEBUG(cret, "%s:%d: curl error.", __func__, __LINE__);
        return 200 + cret;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_TIMEOUT_MS, 3000);
    if (cret != CURLE_OK) {
        SERVER_DEBUG(cret, "%s:%d: curl error.", __func__, __LINE__);
        return 200 + cret;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_SSLVERSION,
                            CURL_SSLVERSION_TLSv1);
    if (cret != CURLE_OK) {
        SERVER_DEBUG(cret, "%s:%d: curl error.", __func__, __LINE__);
        return 200 + cret;
    }

#if !defined DEBUG
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_WRITEFUNCTION, curl_wfunc);
    if (cret != CURLE_OK) {
        SERVER_DEBUG(cret, "%s:%d: curl error.", __func__, __LINE__);
        return 200 + cret;
    }
#endif  /* !DEBUG */

    /* Send request.  */
#ifdef DEBUG
    curl_easy_setopt(ctx->curlh, CURLOPT_ERRORBUFFER, curl_errbuf);
#endif
    cret = curl_easy_perform(ctx->curlh);
#ifdef DEBUG
    curl_easy_setopt(ctx->curlh, CURLOPT_ERRORBUFFER, NULL);
#endif
    if (cret != CURLE_OK) {
        SERVER_DEBUG(cret, "%s:%d: curl error (%s).", __func__, __LINE__,
                     curl_errbuf);
        return 200 + cret;
    }

    cret = curl_easy_getinfo(ctx->curlh, CURLINFO_RESPONSE_CODE, &respcode);
    if (cret != CURLE_OK) {
        SERVER_DEBUG(cret, "%s:%d: curl error.", __func__, __LINE__);
        return 200 + cret;
    }
    if (respcode == 200) {
        return 0;
    }

    SERVER_DEBUG(0, "[basicauth] OTP authn response: %ld", respcode);
    return EACCES;
}

int
otp_basicauth_server_init(struct otp_server_ctx *otp_ctx,
                          get_config_func_t get_config,
                          struct otp_method_ftable **ftable,
                          void **method_context)
{
    int retval = 0;
    struct otp_method_ftable *ft = NULL;
    struct otp_basicauth_ctx *ctx = NULL;
    CURLcode cret = 0;
    int curl_global_init_done_flag = 0;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        retval = ENOMEM;
        goto errout;
    }
#ifdef DEBUG
    ctx->magic = MAGIC_OTP_BASICAUTH_CTX;
#endif
    ctx->otp_context = otp_ctx;

    ft = calloc(1, sizeof(*ft));
    if (ft == NULL) {
        retval = ENOMEM;
        goto errout;
    }
    ft->server_fini = server_fini;
    ft->server_verify = verify_otp;

    ctx->url = get_config(otp_ctx, NULL, URL_TEMPLATE);

    cret = curl_global_init(CURL_GLOBAL_SSL);
    if (cret != 0) {
        retval = EFAULT;
        SERVER_DEBUG(retval, "[basicauth] curl global init failed.");
        goto errout;
    }
    curl_global_init_done_flag = 1;

    ctx->curlh = curl_easy_init();
    if (ctx->curlh == NULL) {
        retval = EFAULT;
        SERVER_DEBUG(retval, "[basicauth] curl init failed.");
        goto errout;
    }

    *ftable = ft;
    *method_context = ctx;
    return 0;

 errout:
    if (curl_global_init_done_flag) {
        curl_global_cleanup();
    }
    if (ctx->curlh != NULL) {
        curl_easy_cleanup(ctx->curlh);
    }
    free(ctx->url);
    free(ctx);
    free(ft);
    return retval;
}
