/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2006 Red Hat, Inc.
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
#include <syslog.h> /* for LOG_INFO */

#include <ykclient.h>

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

#define YUBIKEY_URL_TEMPLATE "yubikey_url_template"
#define YUBIKEY_CLIENT_ID "yubikey_client_id"

#define YUBIKEY_ID_LENGTH 12
#define YUBIKEY_TOKEN_LENGTH 44

#ifdef DEBUG
#define SERVER_DEBUG(body, ...) krb5_klog_syslog(LOG_DEBUG, "OTP PA: "body, \
                                                 ##__VA_ARGS__)
#define CLIENT_DEBUG(body, ...) fprintf(stderr, "OTP PA: "body, ##__VA_ARGS__)
#else
#define SERVER_DEBUG(body, ...)
#define CLIENT_DEBUG(body, ...)
#endif

struct yubikey_otp_ctx {
    char *otp;
};

struct yubikey_server_ctx {
    ykclient_t *yk_ctx;
    char *url_template;
};

static int
cli_init(krb5_context context, void **blob)
{
    struct yubikey_otp_ctx *ctx = NULL;

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
    struct yubikey_otp_ctx *ctx = blob;

    if (ctx == NULL) {
        return;
    }

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
    struct yubikey_otp_ctx *otp_ctx = plugin_context;

    if (strcmp(attr, "OTP_yubikey") == 0) {
        if (otp_ctx->otp != NULL) {
            krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
                                   "OTP_yubikey can not be given twice\n");
            return KRB5_PREAUTH_FAILED;
        }

        otp_ctx->otp = strdup(value);
        if (otp_ctx->otp == NULL) {
            krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
                                   "Could not dublicate OTP_yubikey value\n");
            return ENOMEM;
        }

        CLIENT_DEBUG("Got Yubikey OTP [%s]\n", otp_ctx->otp);
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
    struct yubikey_otp_ctx *otp_ctx = plugin_context;
    krb5_pa_otp_req otp_req;
    krb5_data *encoded_otp_req = NULL;
    krb5_pa_otp_challenge *otp_challenge = NULL;
    krb5_data encoded_otp_challenge;

    retval = fast_get_armor_key(context, get_data_proc, rock, &armor_key);
    if (retval || armor_key == NULL) {
        CLIENT_DEBUG("Missing armor key\n");
        return EINVAL;
    }

    krb5_free_keyblock_contents(context, as_key);
    retval = krb5_copy_keyblock_contents(context, armor_key, as_key);
    krb5_free_keyblock(context, armor_key);
    if (retval != 0) {
        CLIENT_DEBUG("krb5_copy_keyblock_contents failed\n");
        return retval;
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
                return retval;
            }
        }

        if (otp_challenge->nonce.data == NULL) {
            CLIENT_DEBUG("Missing nonce in OTP challenge.\n");
            return EINVAL;
        }

        memset(&otp_req, 0, sizeof(otp_req));

        retval = krb5_c_encrypt_length(context, as_key->enctype,
                                       otp_challenge->nonce.length,
                                       &otp_req.enc_data.ciphertext.length);
        if (retval != 0) {
            CLIENT_DEBUG("krb5_c_encrypt_length failed.\n");
            return retval;
        }

        otp_req.enc_data.ciphertext.data = (char *) malloc(otp_req.enc_data.ciphertext.length);
        if (otp_req.enc_data.ciphertext.data == NULL) {
            CLIENT_DEBUG("malloc failed.\n");
            return ENOMEM;
        }

        retval = krb5_c_encrypt(context, as_key, KRB5_KEYUSAGE_PA_OTP_REQUEST,
                                NULL, &otp_challenge->nonce, &otp_req.enc_data);
        if (retval != 0) {
            CLIENT_DEBUG("Failed to encrypt nonce.\n");
            return retval;
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
            CLIENT_DEBUG("Missing client context\n");
        } else {
            otp_req.otp_value.data = otp_ctx->otp;
            otp_req.otp_value.length = strlen(otp_ctx->otp);
        }

        retval = encode_krb5_pa_otp_req(&otp_req, &encoded_otp_req);
        if (retval != 0) {
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
    if (pa_array)
        free(pa_array);
    if (pa)
        free(pa);

    return retval;
}

/* Server.  */
static krb5_error_code
check_token_id(krb5_context kcontext, const char *token,
               const krb5_principal principal,
               struct _krb5_db_entry_new *client)
{
    krb5_tl_data *tl_data;

    if (strlen(token) != YUBIKEY_TOKEN_LENGTH) {
        return EINVAL;
    }

    tl_data = client->tl_data;
    while (tl_data != NULL) {
        if (tl_data->tl_data_type == KRB5_TL_YUBIKEY_ID) {
            break;
        }
        tl_data = tl_data->tl_data_next;
    }

    if (tl_data == NULL) {
        return ENOENT;
    }

    if (tl_data->tl_data_length != (YUBIKEY_ID_LENGTH + 1) ||
        tl_data->tl_data_contents[YUBIKEY_ID_LENGTH] != '\0') {
        return EINVAL;
    }

    if (memcmp(token, tl_data->tl_data_contents, YUBIKEY_ID_LENGTH) == 0) {
        return 0;
    }

    SERVER_DEBUG("Cannot map token [%s] to principal", token);

    return ENOENT;
}

static int
server_get_flags(krb5_context kcontext, krb5_preauthtype pa_type)
{
    return PA_HARDWARE | PA_REPLACES_KEY;
}

static krb5_error_code
server_init(krb5_context context,
            void **plugin_context,
            const char** realmnames)
{
    int ret;
    struct yubikey_server_ctx *ctx = NULL;
    krb5_error_code retval;
    int client_id = 0;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return ENOMEM;
    }

    ret = ykclient_init(&ctx->yk_ctx);
    if (ret != YKCLIENT_OK) {
        SERVER_DEBUG("ykclient_init failed\n");
        return EFAULT;
    }

/* set URL template from krb5.conf */
    retval = profile_get_string(context->profile, KRB5_CONF_REALMS,
                                context->default_realm, YUBIKEY_URL_TEMPLATE,
                                NULL, &ctx->url_template);
    if (retval != 0) {
        SERVER_DEBUG("Failed to retrive URL template");
        return retval;
    }

    if (ctx->url_template != NULL) {
        ykclient_set_url_template(ctx->yk_ctx, ctx->url_template);
    }
/* set client id and key from krb5.conf */
    retval = profile_get_integer(context->profile, KRB5_CONF_REALMS,
                                context->default_realm, YUBIKEY_CLIENT_ID,
                                0, &client_id);
    if (retval != 0) {
        SERVER_DEBUG("Failed to retrive client id");
        return retval;
    }

    if (client_id > 0) {
        ykclient_set_client(ctx->yk_ctx, client_id, 0, NULL);
    } else {
        SERVER_DEBUG("Missing Yubico client ID");
        return EINVAL;
    }

    *plugin_context = ctx;

    return 0;
}

static void
server_fini(krb5_context context,
            void *plugin_context)
{
    struct yubikey_server_ctx *ctx = plugin_context;

    free(ctx->url_template);
    ykclient_done(&ctx->yk_ctx);
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

    retval = fast_kdc_get_armor_key(context, server_get_entry_data, request,
                                    client, &armor_key);
    if (retval != 0 || armor_key == NULL) {
        SERVER_DEBUG("No armor key found failed\n");
        krb5_free_keyblock(context, armor_key);
        return EINVAL;
    }

    tl_data = client->tl_data;
    while (tl_data != NULL) {
        if (tl_data->tl_data_type == KRB5_TL_YUBIKEY_ID) {
            break;
        }
        tl_data = tl_data->tl_data_next;
    }

    if (tl_data == NULL) {
        SERVER_DEBUG("No Yubikey ID found");
        return ENOENT;
    }
    SERVER_DEBUG("Yubikey ID found, sending OTP Challenge");

    memset(&otp_challenge, 0, sizeof(otp_challenge));
/* "This nonce string MUST be as long as the longest key length of the
 * symmetric key types that the KDC supports and MUST be chosen randomly."
 *
 * FIXME: how do I find out the length of the longest key? I take 256 bits for
 * a start. */
    otp_challenge.nonce.length = 32;
    otp_challenge.nonce.data = (char *) malloc(otp_challenge.nonce.length + 1);
    if (otp_challenge.nonce.data == NULL) {
        SERVER_DEBUG("malloc failed\n");
        return ENOMEM;
    }
    retval = krb5_c_random_make_octets(context, &otp_challenge.nonce);
    if(retval != 0) {
        SERVER_DEBUG("krb5_c_random_make_octets failed\n");
        return retval;
    }

    otp_challenge.otp_keyinfo.flags = -1;

    retval = encode_krb5_pa_otp_challenge(&otp_challenge, &encoded_otp_challenge);
    if (retval != 0) {
        SERVER_DEBUG("encode_krb5_pa_otp_challenge failed\n");
        return retval;
    }

    pa_data->pa_type = KRB5_PADATA_OTP_CHALLENGE;
    pa_data->contents = (krb5_octet *) encoded_otp_challenge->data;
    pa_data->length = encoded_otp_challenge->length;

    return 0;
}

static krb5_error_code
server_verify_preauth(krb5_context context, struct _krb5_db_entry_new *client,
                   krb5_data *req_pkt, krb5_kdc_req *request,
                   krb5_enc_tkt_part *enc_tkt_reply, krb5_pa_data *data,
                   preauth_get_entry_data_proc server_get_entry_data,
                   void *pa_module_context, void **pa_request_context,
                   krb5_data **e_data, krb5_authdata ***authz_data)
{
    krb5_pa_otp_req *otp_req;
    krb5_error_code retval = 0;
    krb5_data encoded_otp_req;
    struct yubikey_server_ctx *ctx = pa_module_context;
    char *otp;
    int ret;
    krb5_keyblock *armor_key = NULL;
    krb5_data decrypted_data;

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

    SERVER_DEBUG("Yubikey (%.*s)", otp_req->otp_value.length,
                                   otp_req->otp_value.data);
    otp = strndup(otp_req->otp_value.data, otp_req->otp_value.length);
    if (otp == NULL) {
        SERVER_DEBUG("strndup failed");
        krb5_free_keyblock(context, armor_key);
        return ENOMEM;
    }

    ret = check_token_id(context, otp, request->client, client);
    if (ret != 0) {
        SERVER_DEBUG("check_token_id failed");
        free(otp);
        krb5_free_keyblock(context, armor_key);
        return ret;
    }

    ret = ykclient_request (ctx->yk_ctx, otp);
    free(otp);

    SERVER_DEBUG("Yubikey auth result: [%s]", ykclient_strerror(ret));


    if (ret != YKCLIENT_OK) {
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
        SERVER_DEBUG("Copying reply key failed.\n");
        return retval;
    }

    return 0;
}

krb5_preauthtype supported_pa_types[] = {
    KRB5_PADATA_OTP_CHALLENGE, KRB5_PADATA_OTP_REQUEST, 0};

struct krb5plugin_preauth_server_ftable_v1 preauthentication_server_1 = {
    "Yubikey OPT",
    &supported_pa_types[0],
    server_init,
    server_fini,
    server_get_flags,
    server_get_edata,
    server_verify_preauth,
    server_return,
    NULL
};

struct krb5plugin_preauth_client_ftable_v1 preauthentication_client_1 = {
    "Yubikey OTP",                /* name */
    &supported_pa_types[0],
    NULL,                    /* enctype_list */
    cli_init,                    /* plugin init function */
    cli_fini,                    /* plugin fini function */
    preauth_flags,
    NULL,                    /* request init function */
    NULL,                    /* request fini function */
    process_preauth,
    NULL,                    /* try_again function */
    get_gic_opts             /* get init creds opt function */
};
