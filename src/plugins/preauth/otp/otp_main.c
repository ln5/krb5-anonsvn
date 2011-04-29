/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2006 Red Hat, Inc.
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

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <syslog.h>             /* for LOG_INFO */
#include <curl/curl.h>

#include "../lib/krb5/asn.1/asn1_encode.h"

#include <krb5/preauth_plugin.h>

#include "../fast_factor.h"
#include <kdb.h>
#include "adm_proto.h" /* for krb5_klog_syslog */

#define KRB5_PADATA_OTP_CHALLENGE  141
#define KRB5_PADATA_OTP_REQUEST    142
#define KRB5_PADATA_OTP_CONFIRM    143
#define KRB5_PADATA_OTP_PIN_CHANGE 144

#define OTP_FLAG_RESERVED 0
#define OTP_FLAG_NEXT_OTP (1u<<1)
#define OTP_FLAG_COMBINE (1u<<2)
#define OTP_FLAG_PIN_REQUIRED (1u<<3)
#define OTP_FLAG_PIN_NOT_REQUIRED (1u<<4)
#define OTP_FLAG_MUST_ENCRYPT_NONCE (1u<<5)

#define OATH_URL_TEMPLATE "otp_url_template"
#define OATH_SUCCESS_RESPONSE "otp_success_response"

#ifdef OATH_SPECIFIC
/* A (class A) OATH token identifier as specified in
   http://www.openauthentication.org/oath-id: MMTTUUUUUUUU.
   M=manufacturer, T=token type, U=manufacturer unique id.  */
#define OATH_ID_LENGTH 12

/* We expect PA data attribute "OTP_OATH" to contain a string containg
   an HOTP OTP (RFC 4226), i.e. between 6 and 8 decimal digits.  */
#define OATH_OTP_LENGTH 8
#endif  /* OATH_SPECIFIC */

#ifdef DEBUG
#define SERVER_DEBUG(body, ...) krb5_klog_syslog(LOG_DEBUG, "OTP PA: "body, \
                                                 ##__VA_ARGS__)
#define CLIENT_DEBUG(body, ...) fprintf(stderr, "OTP PA: "body, ##__VA_ARGS__)
#else
#define SERVER_DEBUG(body, ...)
#define CLIENT_DEBUG(body, ...)
#endif

struct otp_client_ctx {
    char *otp;
};

struct otp_server_ctx {
    CURL *curlh;
    char *url_template;
    char *success_response;
    char *token_id;
};

/* Client.  */
static krb5_preauthtype cli_supported_pa_types[] =
    {KRB5_PADATA_OTP_CHALLENGE, 0};

static int
cli_init(krb5_context context, void **blob)
{
    struct otp_client_ctx *ctx = NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return ENOMEM;
    }

    *blob = ctx;

    return 0;
}

static void
cli_fini(krb5_context context, void *blob)
{
    struct otp_client_ctx *ctx = blob;

    if (ctx == NULL) {
        return;
    }

    if (ctx->otp != NULL)
        free(ctx->otp);
    free(ctx);
}

static int
preauth_flags(krb5_context context, krb5_preauthtype pa_type)
{
    return PA_REAL;
}

static krb5_error_code
get_gic_opts(krb5_context context,
             void *plugin_context,
             krb5_get_init_creds_opt *gic_opt,
             const char *attr,
             const char *value)
{
    struct otp_client_ctx *otp_ctx = plugin_context;

    if (strcmp(attr, "OTP") == 0) {
        if (otp_ctx->otp != NULL) {
            krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
                                   "OTP can not be given twice\n");
            return KRB5_PREAUTH_FAILED;
        }

        otp_ctx->otp = strdup(value);
        if (otp_ctx->otp == NULL) {
            krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
                                   "Unable to copy OTP\n");
            return ENOMEM;
        }

        CLIENT_DEBUG("Got OTP [%s]\n", otp_ctx->otp);
    }

    return 0;
}

static krb5_error_code
process_preauth(krb5_context context, void *plugin_context,
                void *request_context, krb5_get_init_creds_opt *opt,
                preauth_get_client_data_proc get_data_proc,
                struct _krb5_preauth_client_rock *rock, krb5_kdc_req *request,
                krb5_data *encoded_request_body,
                krb5_data *encoded_previous_request, krb5_pa_data *padata,
                krb5_prompter_fct prompter, void *prompter_data,
                preauth_get_as_key_proc gak_fct, void *gak_data,
                krb5_data *salt, krb5_data *s2kparams, krb5_keyblock *as_key,
                krb5_pa_data ***out_padata)
{
    krb5_error_code retval = 0;
    krb5_keyblock *armor_key = NULL;
    krb5_pa_data *pa = NULL;
    krb5_pa_data **pa_array = NULL;
    struct otp_client_ctx *otp_ctx = plugin_context;
    krb5_pa_otp_req otp_req;
    krb5_data *encoded_otp_req = NULL;
    krb5_pa_otp_challenge *otp_challenge = NULL;
    krb5_data encoded_otp_challenge;

    CLIENT_DEBUG("%s: enter\n", __func__);

    retval = fast_get_armor_key(context, get_data_proc, rock, &armor_key);
    if (retval != 0 || armor_key == NULL) {
        CLIENT_DEBUG("Missing armor key\n");
        goto errout;
    }

    krb5_free_keyblock_contents(context, as_key);
    retval = krb5_copy_keyblock_contents(context, armor_key, as_key);
    krb5_free_keyblock(context, armor_key);
    if (retval != 0) {
        CLIENT_DEBUG("krb5_copy_keyblock_contents failed\n");
        goto errout;
    }

    CLIENT_DEBUG("Got [%d] bytes padata type [%d]\n", padata->length,
                 padata->pa_type);

    if (padata->pa_type == KRB5_PADATA_OTP_CHALLENGE) {
        if (padata->length != 0) {
            encoded_otp_challenge.data = (char *) padata->contents;
            encoded_otp_challenge.length = padata->length;
            retval = decode_krb5_pa_otp_challenge(&encoded_otp_challenge,
                                                  &otp_challenge);
            if (retval != 0) {
                goto errout;
            }
        }

        if (otp_challenge->nonce.data == NULL) {
            CLIENT_DEBUG("Missing nonce in OTP challenge.\n");
            retval = EINVAL;
            goto errout;
        }

        memset(&otp_req, 0, sizeof(otp_req));

        retval = krb5_c_encrypt_length(context, as_key->enctype,
                                       otp_challenge->nonce.length,
                                       (size_t *) &otp_req.enc_data.ciphertext.length);
        if (retval != 0) {
            CLIENT_DEBUG("krb5_c_encrypt_length failed.\n");
            goto errout;
        }

        otp_req.enc_data.ciphertext.data =
            (char *) malloc(otp_req.enc_data.ciphertext.length);
        if (otp_req.enc_data.ciphertext.data == NULL) {
            CLIENT_DEBUG("Out of memory.\n");
            retval = ENOMEM;
            goto errout;
        }

        retval = krb5_c_encrypt(context, as_key, KRB5_KEYUSAGE_PA_OTP_REQUEST,
                                NULL, &otp_challenge->nonce, &otp_req.enc_data);
        if (retval != 0) {
            CLIENT_DEBUG("Failed to encrypt nonce.\n");
            goto errout;
        }

        pa = calloc(1, sizeof(krb5_pa_data));
        if (pa == NULL) {
            retval = ENOMEM;
            goto errout;
        }

        pa_array = calloc(2, sizeof(krb5_pa_data *));
        if (pa_array == NULL) {
            retval = ENOMEM;
            goto errout;
        }

        if (otp_ctx->otp == NULL) {
            CLIENT_DEBUG("Missing client context.\n");
        } else {
            otp_req.otp_value.data = otp_ctx->otp;
            otp_req.otp_value.length = strlen(otp_ctx->otp);
        }

        retval = encode_krb5_pa_otp_req(&otp_req, &encoded_otp_req);
        if (retval != 0) {
            CLIENT_DEBUG("encode_krb5_pa_otp_req failed.\n");
            goto errout;
        }

        pa->length = encoded_otp_req->length;
        pa->contents = (unsigned char *) encoded_otp_req->data;
        pa->pa_type = KRB5_PADATA_OTP_REQUEST;

        pa_array[0] = pa;
        *out_padata = pa_array;
    } else {
        CLIENT_DEBUG("Unexpected PA data.\n");
        return EINVAL;
    }

    CLIENT_DEBUG("Successfully processed PA data.\n");

    return 0;

 errout:
    if (pa_array != NULL)
        free(pa_array);
    if (pa != NULL)
        free(pa);

    return retval;
}


/* Server.  */
#if 0                           /* Done in server_get_edata().  */
static krb5_error_code
get_token_id(krb5_context kcontext,
             struct _krb5_db_entry_new *client,
             struct otp_server_ctx *otp_ctx,
             unsigned const char *token)
{
    krb5_tl_data *tl_data;

    SERVER_DEBUG("%s: enter", __func__);

#ifdef OATH_SPECIFIC
    if (strlen(token) != OATH_ID_LENGTH) {
        return EINVAL;
    }
#endif  /* OATH_SPECIFIC */

    /* Find token id in kdb.  */
    tl_data = client->tl_data;
    while (tl_data != NULL) {
        if (tl_data->tl_data_type == KRB5_TL_OTP_ID) {
            break;
        }
        tl_data = tl_data->tl_data_next;
    }
    if (tl_data == NULL) {
        return ENOENT;
    }

#ifdef OATH_SPECIFIC
    if (tl_data->tl_data_length != (OATH_ID_LENGTH + 1) ||
        tl_data->tl_data_contents[OATH_ID_LENGTH] != '\0') {
        return EINVAL;
    }
    if (memcmp(token, tl_data->tl_data_contents, OATH_ID_LENGTH) == 0) {
        SERVER_DEBUG("Token mapped: [%s]", token);
        return 0;               /* Success.  */
    }
#else  /* !OATH_SPECIFIC */
    if (token == NULL
        || strcmp((const char *) token,
                  (const char *) tl_data->tl_data_contents) == 0) {
        SERVER_DEBUG("Token mapped: [%s]", token);
        return 0;               /* Success.  */
    }
#endif  /* !OATH_SPECIFIC */

    SERVER_DEBUG("Cannot map token [%s] to principal [%s]", token, "FIXME");
    return ENOENT;
}
#endif

static int
server_get_flags(krb5_context kcontext, krb5_preauthtype pa_type)
{
    return PA_HARDWARE | PA_REPLACES_KEY;
}

static krb5_error_code
server_init(krb5_context context,
            void **pa_module_context,
            const char** realmnames)
{
    struct otp_server_ctx *ctx = NULL;
    krb5_error_code retval = 0;
    CURLcode cret = 0;

    assert(pa_module_context != NULL);

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        retval = ENOMEM;
        goto errout;
    }

    cret = curl_global_init(CURL_GLOBAL_SSL);
    if (cret != 0) {
        SERVER_DEBUG("curl global init failed");
        retval = EFAULT;
        goto errout;
    }
    ctx->curlh = curl_easy_init();
    if (ctx->curlh == NULL) {
        SERVER_DEBUG("curl init failed");
        retval = EFAULT;
        goto errout;
    }

    /* Get URL template from KDC config.  */
    retval = profile_get_string(context->profile, KRB5_CONF_REALMS,
                                context->default_realm, OATH_URL_TEMPLATE,
                                NULL, &ctx->url_template);
    if (retval != 0) {
        SERVER_DEBUG("Failed to retrive URL template");
        goto errout;
    }

    /* Get success reponse string from KDC config.  */
    retval = profile_get_string(context->profile, KRB5_CONF_REALMS,
                                context->default_realm, OATH_SUCCESS_RESPONSE,
                                NULL, &ctx->success_response);
    if (retval != 0) {
        SERVER_DEBUG("Failed to retrive success response string");
        goto errout;
    }

    *pa_module_context = ctx;

    return 0;

 errout:
    if (ctx != NULL)
        free (ctx);
    return retval;
}

static void
server_fini(krb5_context context, void *pa_module_context)
{
    struct otp_server_ctx *ctx = pa_module_context;

    curl_easy_cleanup(ctx->curlh);
    curl_global_cleanup();

    assert(ctx != NULL);
    if (ctx->token_id != NULL)
        free(ctx->token_id);
    free(ctx);
}

static krb5_error_code
server_get_edata(krb5_context context,
                 krb5_kdc_req *request,
                 struct _krb5_db_entry_new *client,
                 struct _krb5_db_entry_new *server,
                 preauth_get_entry_data_proc server_get_entry_data,
                 void *pa_module_context,
                 krb5_pa_data *pa_data)
{
    krb5_error_code retval = 0;
    krb5_keyblock *armor_key = NULL;
    krb5_pa_otp_challenge otp_challenge;
    krb5_data *encoded_otp_challenge = NULL;
    krb5_tl_data *tl_data;
    struct otp_server_ctx *otp_ctx = pa_module_context;

    SERVER_DEBUG("%s: enter", __func__);
    assert(otp_ctx != NULL);

    retval = fast_kdc_get_armor_key(context, server_get_entry_data, request,
                                    client, &armor_key);
    if (retval != 0 || armor_key == NULL) {
        SERVER_DEBUG("No armor key found");
        krb5_free_keyblock(context, armor_key);
        return EINVAL;
    }

    /* Find (the right) token id.  Store a copy of it in otp_ctx.  */
    tl_data = client->tl_data;
    while (tl_data != NULL) {
        if (tl_data->tl_data_type == KRB5_TL_OTP_ID) {
            /* TODO: Match with value of padata "OTP_ID".  */
            break;
        }
        tl_data = tl_data->tl_data_next;
    }

    if (tl_data == NULL) {
        SERVER_DEBUG("OTP token id not found for principal");
        return ENOENT;
    }

    otp_ctx->token_id = strndup((const char *) tl_data->tl_data_contents,
                                tl_data->tl_data_length);
    if (otp_ctx->token_id == NULL) {
        SERVER_DEBUG("Unable to copy token id.");
        return ENOMEM;
    }

    SERVER_DEBUG("OTP token id [%s] found, sending OTP challenge",
                 otp_ctx->token_id);

    memset(&otp_challenge, 0, sizeof(otp_challenge));
/* "This nonce string MUST be as long as the longest key length of the
 * symmetric key types that the KDC supports and MUST be chosen randomly."
 *
 * FIXME: how do I find out the length of the longest key? I take 256 bits for
 * a start. */
    otp_challenge.nonce.length = 32;
    otp_challenge.nonce.data = (char *) malloc(otp_challenge.nonce.length + 1);
    if (otp_challenge.nonce.data == NULL) {
        SERVER_DEBUG("malloc failed");
        return ENOMEM;
    }
    retval = krb5_c_random_make_octets(context, &otp_challenge.nonce);
    if(retval != 0) {
        SERVER_DEBUG("krb5_c_random_make_octets failed");
        return retval;
    }

    otp_challenge.otp_keyinfo.flags = -1;

    retval = encode_krb5_pa_otp_challenge(&otp_challenge, &encoded_otp_challenge);
    if (retval != 0) {
        SERVER_DEBUG("encode_krb5_pa_otp_challenge failed");
        return retval;
    }

    pa_data->pa_type = KRB5_PADATA_OTP_CHALLENGE;
    pa_data->contents = (krb5_octet *) encoded_otp_challenge->data;
    pa_data->length = encoded_otp_challenge->length;

    return 0;
}

#if !defined DEBUG
static size_t
curl_wfunc(void *ptr, size_t size, size_t nmemb, void *stream)
{
    return size * nmemb;
}
#endif  /* !DEBUG */

static int
verify_otp(const struct otp_server_ctx *ctx, const char *pw)
{
    CURLcode cret = 0;
    char *url = NULL;
    long respcode = 0;
#ifdef DEBUG
    char curl_errbuf[CURL_ERROR_SIZE];
#endif

    SERVER_DEBUG("%s: "
                 "url_template=[%s] success_response=[%s]"
                 "token id=[%s] pw=[%s]",
                 __func__,
                 ctx->url_template, ctx->success_response,
                 ctx->token_id, pw);

    assert(ctx != NULL);
    assert(pw != NULL);

    if (ctx->url_template == NULL) {
        SERVER_DEBUG("Missing otp_url_template in krb5.conf.");
        return -1;
    }
    if (strstr(ctx->url_template, "%s") == NULL) {
        url = ctx->url_template;
    }
    else {
        snprintf(url, sizeof(url), ctx->url_template, ctx->token_id, pw);
    }

    cret = curl_easy_setopt(ctx->curlh, CURLOPT_URL, url);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return -1;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return -1;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_USERNAME, ctx->token_id);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return -1;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_PASSWORD, pw);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return -1;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_TIMEOUT_MS, 3000);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return -1;
    }
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_SSLVERSION,
                            CURL_SSLVERSION_TLSv1);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return -1;
    }

#if !defined DEBUG
    cret = curl_easy_setopt(ctx->curlh, CURLOPT_WRITEFUNCTION, curl_wfunc);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return -1;
    }
#endif  /* !DEBUG */

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
        return -1;
    }

    cret = curl_easy_getinfo(ctx->curlh, CURLINFO_RESPONSE_CODE, &respcode);
    if (cret != CURLE_OK) {
        SERVER_DEBUG("%s:%d: curl error %d", __func__, __LINE__, cret);
        return -1;
    }
    if (respcode == 200) {
        SERVER_DEBUG("Successful OTP verification for %s", ctx->token_id);
        return 0;
    }

    SERVER_DEBUG("%s: OTP authn response: %ld", __func__, respcode);
    return -1;
}

static krb5_error_code
server_verify_preauth(krb5_context context,
                      struct _krb5_db_entry_new *client,
                      krb5_data *req_pkt,
                      krb5_kdc_req *request,
                      krb5_enc_tkt_part *enc_tkt_reply,
                      krb5_pa_data *data,
                      preauth_get_entry_data_proc server_get_entry_data,
                      void *pa_module_context,
                      void **pa_request_context,
                      krb5_data **e_data,
                      krb5_authdata ***authz_data)
{
    krb5_pa_otp_req *otp_req = NULL;
    krb5_error_code retval = 0;
    krb5_data encoded_otp_req;
    char *otp = NULL;
    int ret;
    krb5_keyblock *armor_key = NULL;
    krb5_data decrypted_data;
    struct otp_server_ctx *otp_ctx = pa_module_context;

    assert(otp_ctx != NULL);

    encoded_otp_req.length = data->length;
    encoded_otp_req.data = (char *) data->contents;

    retval = decode_krb5_pa_otp_req(&encoded_otp_req, &otp_req);
    if (retval != 0) {
        return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    /* FIXME: So far I only check if some encryted data is present. To verify it
     * the nonce must be put into a PA-FX-COOKIE and I don't know how to do it. */
    if (otp_req->enc_data.ciphertext.data == NULL) {
        SERVER_DEBUG("Missing encrypted data.");
        return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    decrypted_data.length = otp_req->enc_data.ciphertext.length;
    decrypted_data.data = (char *) malloc(decrypted_data.length);
    if (decrypted_data.data == NULL) {
        SERVER_DEBUG("malloc failed.");
        return ENOMEM;
    }

    retval = fast_kdc_get_armor_key(context, server_get_entry_data, request,
                                    client, &armor_key);
    if (retval != 0 || armor_key == NULL) {
        krb5_free_keyblock(context, armor_key);
        return EINVAL;
    }

    retval = krb5_c_decrypt(context, armor_key, KRB5_KEYUSAGE_PA_OTP_REQUEST,
                            NULL, &otp_req->enc_data, &decrypted_data);
    if (retval != 0) {
        SERVER_DEBUG("krb5_c_decrypt failed.");
        krb5_free_data_contents(context, &decrypted_data);
        krb5_free_keyblock(context, armor_key);
        return retval;
    }
    krb5_free_data_contents(context, &decrypted_data);

    SERVER_DEBUG("OTP (%.*s)", otp_req->otp_value.length,
                 otp_req->otp_value.data);
    otp = strndup(otp_req->otp_value.data, otp_req->otp_value.length);
    if (otp == NULL) {
        SERVER_DEBUG("strndup failed");
        krb5_free_keyblock(context, armor_key);
        return ENOMEM;
    }

    ret = verify_otp(otp_ctx, otp);
    free(otp);

    SERVER_DEBUG("OTP auth result: %d", ret);

    if (ret) {
        *pa_request_context = NULL;
        krb5_free_keyblock(context, armor_key);
        return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    *pa_request_context = armor_key;

    enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;
    enc_tkt_reply->flags |= TKT_FLG_HW_AUTH;

    return 0;
}

static krb5_error_code
server_return(krb5_context kcontext,
              krb5_pa_data *padata,
              struct _krb5_db_entry_new *client,
              krb5_data *req_pkt,
              krb5_kdc_req *request,
              krb5_kdc_rep *reply,
              struct _krb5_key_data *client_key,
              krb5_keyblock *encrypting_key,
              krb5_pa_data **send_pa,
              preauth_get_entry_data_proc server_get_entry_data,
              void *pa_module_context,
              void **pa_request_context)
{
    krb5_keyblock *reply_key = NULL;
    krb5_error_code retval;

    SERVER_DEBUG("%s: enter", __func__);
    if (pa_request_context == NULL || *pa_request_context == NULL) {
        SERVER_DEBUG("Not handled by me.");
        return 0;
    }

    reply_key = (krb5_keyblock *) *pa_request_context;
    *pa_request_context = NULL;

    krb5_free_keyblock_contents(kcontext, encrypting_key);
    retval = krb5_copy_keyblock_contents(kcontext, reply_key, encrypting_key);
    krb5_free_keyblock(kcontext, reply_key);
    if (retval != 0) {
        SERVER_DEBUG("Copying reply key failed.");
        return retval;
    }

    return 0;
}

static krb5_preauthtype server_supported_pa_types[] =
    {KRB5_PADATA_OTP_REQUEST, 0};

struct krb5plugin_preauth_server_ftable_v1 preauthentication_server_1 = {
    "OTP",
    server_supported_pa_types,
    server_init,
    server_fini,
    server_get_flags,
    server_get_edata,
    server_verify_preauth,
    server_return,
    NULL
};

struct krb5plugin_preauth_client_ftable_v1 preauthentication_client_1 = {
    "OTP",                      /* name */
    cli_supported_pa_types,
    NULL,                       /* enctype_list */
    cli_init,
    cli_fini,
    preauth_flags,
    NULL,                       /* request init function */
    NULL,                       /* request fini function */
    process_preauth,
    NULL,                       /* try_again function */
    get_gic_opts                /* get init creds opt function */
};
