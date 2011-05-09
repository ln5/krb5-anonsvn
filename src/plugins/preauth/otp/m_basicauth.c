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
    search_db_func_t search_db;

    CURL *curlh;
    char *url_template;
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
    if (ctx->url_template != NULL) {
        free(ctx->url_template);
    }
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
verify_otp(const struct otp_server_ctx *otp_ctx, const char *pw)
{
    struct otp_basicauth_ctx *ctx;
    CURLcode cret = 0;
    char urlbuf[120];
    char *url = NULL;
    char *username = NULL;
    long respcode = 0;
    int format_flag;
    int count;
    char *cp = NULL;
#ifdef DEBUG
    char curl_errbuf[CURL_ERROR_SIZE];
#endif
    assert(otp_ctx != NULL);
#ifdef DEBUG
    assert(otp_ctx->magic == MAGIC_OTP_SERVER_CTX);
#endif

    ctx = otp_ctx->method->context;
#ifdef DEBUG
    assert(ctx->magic == MAGIC_OTP_BASICAUTH_CTX);
#endif

    SERVER_DEBUG("%s: "
                 "url_template=[%s] "
                 "token id=[%s] pw=[%s]",
                 __func__,
                 ctx->url_template,
                 otp_ctx->token_id, pw);

    assert(ctx != NULL);

    if (pw == NULL) {
        SERVER_DEBUG("%s: missing OTP", __func__);
        return EINVAL;
    }

    /* Blob contains username.  */
    if (ctx->otp_context->blob == NULL) {
        SERVER_DEBUG("[OTP basicauth] Missing blob.");
        return EINVAL;
    }
    if (ctx->otp_context->blob[ctx->otp_context->blobsize] != '\0') {
        SERVER_DEBUG("Invalid blob of length %lu.", ctx->otp_context->blobsize);
        return EINVAL;
    }
    username = ctx->otp_context->blob;

    /* Find out URL.  The URL template is taken from krb5.conf.  If it
       contains any formatting directives (i.e. any '%') they must be
       string directives ('%s') and be exactly two -- the first for
       token id and the second for the OTP.  */
    if (ctx->url_template == NULL) {
        SERVER_DEBUG("Missing otp_url_template in krb5.conf.");
        return EINVAL;
    }
    format_flag = 0;
    count = 0;
    for (cp = ctx->url_template; *cp != '\0'; cp++) {
        if (*cp == '%') {
            format_flag = 1;
            if (*++cp == 's') {
                if (++count == 2) {
                    break;
                }
            }
        }
    }
    if (format_flag) {
        if (count == 2) {
            snprintf(urlbuf, sizeof(urlbuf), ctx->url_template,
                     otp_ctx->token_id, pw);
            url = urlbuf;
        }
        else {
            SERVER_DEBUG("[m_basicauth] Invalid URL template: [%s]",
                         ctx->url_template);
            SERVER_DEBUG("[m_basicauth] The URL template may contain two "
                         "\"%%s\"");
            return EINVAL;
        }
    }
    else {
        url = ctx->url_template;
    }

    SERVER_DEBUG("[m_basicauth] Using URL [%s]", url);

    /* Set curl options.  */
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_URL, url);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return 200 + cret;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return 200 + cret;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_USERNAME, username);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return 200 + cret;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_PASSWORD, pw);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return 200 + cret;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_TIMEOUT_MS, 3000);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return 200 + cret;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_SSLVERSION,
                            CURL_SSLVERSION_TLSv1);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return 200 + cret;
    }

#if !defined DEBUG
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_WRITEFUNCTION, curl_wfunc);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
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
        SERVER_DEBUG("%s:%d: curl error %d (%s)", __func__, __LINE__, cret,
                     curl_errbuf);
        return 200 + cret;
    }

    cret = curl_easy_getinfo(ctx->curlh, CURLINFO_RESPONSE_CODE, &respcode);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return 200 + cret;
    }
    if (respcode == 200) {
        return 0;
    }

    SERVER_DEBUG("[m_basicauth] OTP authn response: %ld", respcode);
    return EACCES;
}

int
otp_basicauth_server_init(struct otp_server_ctx *otp_ctx,
                          get_config_func_t get_config,
                          search_db_func_t search_db,
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

    ctx->url_template = get_config(otp_ctx, NULL, URL_TEMPLATE);

    cret = curl_global_init(CURL_GLOBAL_SSL);
    if (cret != 0) {
        SERVER_DEBUG("curl global init failed");
        retval = EFAULT;
        goto errout;
    }
    curl_global_init_done_flag = 1;

    ctx->curlh = curl_easy_init();
    if (ctx->curlh == NULL) {
        SERVER_DEBUG("curl init failed");
        retval = EFAULT;
        goto errout;
    }

    *ftable = ft;
    *method_context = ctx;
    return 0;

 errout:
    if (curl_global_init_done_flag)
        curl_global_cleanup();
    if (ctx->curlh != NULL)
        curl_easy_cleanup(ctx->curlh);
    if (ctx->url_template != NULL)
        free(ctx->url_template);
    if (ctx != NULL)
        free(ctx);
    if (ft != NULL)
        free(ft);
    return retval;
}
