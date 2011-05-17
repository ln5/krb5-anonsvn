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

/*
  A successful OTP authentication follows this process on the KDC.

  (1) The kdb is searched for an OTP token identity (KRB5_TL_OTP_ID),
      matching what might be found in preauth attribute "OTP_TOKENID".

  (2) An authn method, i.e. a function, is picked from the result of
      (1).

  (3) The kdb is searched for an OTP method data blob
      (KRB5_TL_OTP_BLOB) matching the token id used.

  (4) The authn method from (2) is invoked with the binary blob from
      (3).

  (5) The result from (4) is returned.


  Two new [tl-data] are defined for the krbExtraData [field] in the
  Kerberos database, KRB5_TL_OTP_ID and KRB5_TL_OTP_BLOB.

  KRB5_TL_OTP_ID is a string with two tokens separated by a colon.

    <otp-token-id>:<method-name>

    otp-token-id identifies a unique token on the form of a class A
    OATH token identifier as specified in
    http://www.openauthentication.org/oath-id: MMTTUUUUUUUU.
    M=manufacturer, T=token type, U=manufacturer unique id
    method-name.

    method-name identifies the method to use for authentication,
    f.ex. "basicauth", "ykclient" or "nativehotp".  The method name
    maps to a function in the OTP plugin or possibly in a second-level
    plugin.  A method may use the prefix "otp_<method-name>_" for
    profile names in krb5.conf.

  KRB5_TL_OTP_BLOB is a binary blob tagged with a token id.

    <otp-token-id>:<binary-blob>

    otp-token-id is the same token identifier as found in a
    KRB5_TL_OTP_ID.

    binary-blob is a binary blob passed to the authentication method
    chosen based on the KRB5_TL_OTP_ID.

  A token id may be passed to the KDC using the pre-authentication
  attribute "OTP_TOKENID".  If no OTP_TOKENID is provided, the first
  KRB5_TL_OTP_ID found in the kdb is used.
 */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include "../lib/krb5/asn.1/asn1_encode.h"
#include <krb5/preauth_plugin.h>
#include "../fast_factor.h"

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

/* A (class A) OATH token identifier as specified in
   http://www.openauthentication.org/oath-id: MMTTUUUUUUUU.
   M=manufacturer, T=token type, U=manufacturer unique id.  */
#define TOKEN_ID_LENGTH 12

#include "otp.h"
#include "m_basicauth.h"
#include "m_ykclient.h"

/* Configured OTP methods.  */
struct otp_method otp_methods[] = {
    {"basicauth", otp_basicauth_server_init, 0, NULL, NULL},
    {"ykclient", otp_ykclient_server_init, 0, NULL, NULL},
    {NULL, NULL, 0, NULL, NULL}
};

/**********/
/* Util.  */
/* Return the length of "the longest key length of the symmetric key
   types that the KDC supports" or 0 on failure.  */
static size_t
maxkeylength(krb5_context context)
{
    krb5_error_code retval;
    size_t max;
    krb5_enctype *enctypes = NULL;

    retval = krb5_get_permitted_enctypes(context, &enctypes);
    if (retval != 0) {
        SERVER_DEBUG("krb5_get_permitted_enctypes() fail");
        return 0;
    }

    max = 0;
    while (*enctypes != 0) {
        size_t keybytes, keylength;

        retval = krb5_c_keylengths(context, *enctypes, &keybytes, &keylength);
        if (retval != 0) {
            SERVER_DEBUG("krb5_c_keylengths() fail");
            return 0;
        }
        if (keylength > max) {
            max = keylength;
        }
        enctypes++;
    }

    return max;
}

/************/
/* Client.  */
#if defined(DEBUG)
char *
_format_nonce(const krb5_data *nonce);
char *
_format_nonce(const krb5_data *nonce)
{
    char *s = NULL;
    unsigned int f;

    s = calloc(1, 2 * nonce->length + 1);
    assert(s != NULL);
    for (f = 0; f < nonce->length; f++) {
        sprintf(s + f * 2, "%02x", nonce->data[f] & 0xff);
    }
    return s;
}
#endif  /* DEBUG */

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

        CLIENT_DEBUG("Got OTP [%s].\n", otp_ctx->otp);
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

    retval = fast_get_armor_key(context, get_data_proc, rock, &armor_key);
    if (retval != 0 || armor_key == NULL) {
        CLIENT_DEBUG("Missing armor key.\n");
        goto errout;
    }

    krb5_free_keyblock_contents(context, as_key);
    retval = krb5_copy_keyblock_contents(context, armor_key, as_key);
    krb5_free_keyblock(context, armor_key);
    if (retval != 0) {
        CLIENT_DEBUG("krb5_copy_keyblock_contents failed.\n");
        goto errout;
    }

    CLIENT_DEBUG("Got [%d] bytes padata type [%d].\n", padata->length,
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
#ifdef DEBUG
        {
            char *s = _format_nonce(&otp_challenge->nonce);
            CLIENT_DEBUG("Nonce: [%s]\n", s);
            free(s);
        }
#endif  /* DEBUG */

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
    free(pa_array);
    free(pa);
    return retval;
}


/************/
/* Server.  */
static int
server_get_flags(krb5_context kcontext, krb5_preauthtype pa_type)
{
    return PA_HARDWARE | PA_REPLACES_KEY;
}

static char *
get_config(struct otp_server_ctx *otp_ctx,
           const char *realm_in,
           const char *str)
{
    krb5_context k5_ctx = NULL;
    krb5_error_code retval = 0;
    char *result = NULL;
    const char *realm = realm_in;
    assert(otp_ctx != NULL);

    k5_ctx = otp_ctx->krb5_context;
    assert(k5_ctx != NULL);

    if (realm == NULL) {
        realm = k5_ctx->default_realm;
    }
    retval = profile_get_string(k5_ctx->profile, KRB5_CONF_REALMS, realm, str,
                                NULL, &result);
    if (retval != 0) {
        SERVER_DEBUG("%s: profile_get_string error: %d.", __func__, retval);
    }

    return result;
}

static int
search_db_type(void *krb_ctx,
               int search, /* type */
               void **state,
               struct otp_tlv **tlv_out)
{
    struct otp_server_ctx *ctx = krb_ctx;
    int retval = 0;
    krb5_tl_data *tl_data = NULL;
    struct otp_tlv *tlv = NULL;

    if (state != NULL) {
        tl_data = *state;      /* Note that this may well be NULL.  */
    }
    else {
        if (ctx->client == NULL) {
            SERVER_DEBUG("%s: called before server_get_edata().", __func__);
            retval = EINVAL;
            goto errout;
        }
        tl_data = ctx->client->tl_data;
    }

    while (tl_data != NULL) {
        if (tl_data->tl_data_type == search) {
            tlv = calloc(1, sizeof(*tlv));
            if (tlv == NULL) {
                retval = ENOMEM;
                goto errout;
            }
            tlv->value = calloc(1, tl_data->tl_data_length);
            if (tlv->value == NULL) {
                retval = ENOMEM;
                goto errout;
            }
            memcpy(tlv->value,
                   tl_data->tl_data_contents,
                   tl_data->tl_data_length);
            tlv->type = tl_data->tl_data_type;
            tlv->length = tl_data->tl_data_length;

            if (state != NULL) {
                *state = tl_data->tl_data_next;
            }

            if (tlv_out != NULL) {
                *tlv_out = tlv;
            }
            break;
        }

        tl_data = tl_data->tl_data_next;
    }

    return 0;

 errout:
    if (tlv != NULL) {
        free(tlv->value);
    }
    free(tlv);
    return retval;
}


static void
server_init_methods(struct otp_server_ctx *ctx)
{
    int f;

    for (f = 0; otp_methods[f].name != NULL; f++) {
        struct otp_method *m = &otp_methods[f];
        if (m->init(ctx,
                    get_config,
                    search_db_type,
                    &m->ftable,
                    &m->context) == 0) {
            m->enabled_flag = 1;
        }
        else {
            SERVER_DEBUG("Failing init for method [%s].", m->name);
        }
    }
}

static krb5_error_code
server_init(krb5_context krb5_ctx,
            void **pa_module_context,
            const char** realmnames)
{
    struct otp_server_ctx *ctx = NULL;
    krb5_error_code retval = 0;

    assert(pa_module_context != NULL);

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        retval = ENOMEM;
        goto errout;
    }
#ifdef DEBUG
    ctx->magic = MAGIC_OTP_SERVER_CTX;
#endif

    ctx->krb5_context = krb5_ctx;
    server_init_methods(ctx);
    *pa_module_context = ctx;

    return 0;

 errout:
    free (ctx);
    return retval;
}

static void
server_fini_methods(struct otp_server_ctx *ctx)
{
    int f;

    for (f = 0; otp_methods[f].name != NULL; f++) {
        struct otp_method *m = &otp_methods[f];
        if (m->enabled_flag) {
            assert(m->ftable);
            if (m->ftable->server_fini) {
                m->ftable->server_fini(m->context);
            }
            free (m->ftable);
        }
    }
}

static void
server_fini(krb5_context context, void *pa_module_context)
{
    struct otp_server_ctx *ctx = pa_module_context;
    assert(ctx != NULL);

    server_fini_methods(ctx);
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
                 krb5_pa_data *pa_data,
                 krb5_pa_data *cookie)
{
    krb5_error_code retval = 0;
    krb5_keyblock *armor_key = NULL;
    krb5_pa_otp_challenge otp_challenge;
    krb5_data *encoded_otp_challenge = NULL;
    krb5_tl_data *tl_data;
    struct otp_server_ctx *otp_ctx = pa_module_context;
    char *method_name = NULL;
    char *token_id = NULL;
    int f;

    assert(otp_ctx != NULL);

    retval = fast_kdc_get_armor_key(context, server_get_entry_data, request,
                                    client, &armor_key);
    if (retval != 0 || armor_key == NULL) {
        SERVER_DEBUG("No armor key found.");
        retval = EINVAL;
        goto errout;
    }

    /* Find (the right) token id.  Store a copy of it in otp_ctx.  */
    tl_data = client->tl_data;
    while (tl_data != NULL) {
        if (tl_data->tl_data_type == KRB5_TL_OTP_ID) {
            if (tl_data->tl_data_contents[tl_data->tl_data_length] == '\0') {
                free(token_id);
                token_id = calloc(1, tl_data->tl_data_length);
                if (token_id == NULL) {
                    return ENOMEM;
                }
                memcpy(token_id, tl_data->tl_data_contents,
                       tl_data->tl_data_length);
                method_name = strchr(token_id, ':');
                if (method_name != NULL) {
                    *method_name++ = '\0';
                    /* TODO: Match token_id against PA attribute
                       "OTP_TOKENID".  Use TOKEN_ID_LENGTH.  */
                    break;
                }
            }
        }
        tl_data = tl_data->tl_data_next;
    }

    if (tl_data == NULL) {
        SERVER_DEBUG("OTP token id not found for principal.");
        retval = ENOENT;
        goto errout;
    }
    if (method_name == NULL) {
        SERVER_DEBUG("OTP authentication method not configured for principal");
        retval = ENOENT;
        goto errout;
    }

    for (f = 0; otp_methods[f].name != NULL; f++) {
        if (strcmp(otp_methods[f].name, method_name) == 0) {
            otp_ctx->method = &otp_methods[f];
        }
    }

    if (otp_ctx->method == NULL) {
        SERVER_DEBUG("OTP authentication method %s not configured.",
                     method_name);
        retval = ENOENT;
        goto errout;
    }

    otp_ctx->token_id = token_id;
    SERVER_DEBUG("OTP token id [%s] found, method [%s], sending OTP challenge.",
                 otp_ctx->token_id, method_name);

    memset(&otp_challenge, 0, sizeof(otp_challenge));

    otp_challenge.nonce.length = maxkeylength(context);
    if (otp_challenge.nonce.length == 0) {
        SERVER_DEBUG("%s: Unable to find out length of nonce.", __func__);
        goto errout;
    }
    SERVER_DEBUG("Nonce length is %u bits.", 8 * otp_challenge.nonce.length);
    otp_challenge.nonce.data = (char *) malloc(otp_challenge.nonce.length);
    if (otp_challenge.nonce.data == NULL) {
        retval = ENOMEM;
        goto errout;
    }
    retval = krb5_c_random_make_octets(context, &otp_challenge.nonce);
    if (retval != 0) {
        SERVER_DEBUG("krb5_c_random_make_octets failed.");
        goto errout;
    }

    //otp_challenge.otp_keyinfo.flags |= fixme->keyinfo_flags;
    otp_challenge.otp_keyinfo.flags = -1;

#if defined(DEBUG)
    {
        char *s = _format_nonce(&otp_challenge.nonce);
        SERVER_DEBUG("Nonce: [%s]\n", s);
        free(s);
    }
#endif  /* DEBUG */

    /* Create cookie, include nonce.  */
    /* "[...] the KDC MUST construct the cookie token in such a manner
       that a malicious client cannot subvert the authentication
       process by manipulating the token.  The KDC implementation
       needs to consider expiration of tokens, key rollover, and other
       security issues in token design." */
    if (cookie == NULL) {
        SERVER_DEBUG("No space for a cookie.");
        retval = EINVAL;
        goto errout;
    }
    cookie->contents = malloc(otp_challenge.nonce.length);
    if (cookie->contents == NULL) {
        retval = ENOMEM;
        goto errout;
    }
    cookie->length = otp_challenge.nonce.length;
    memcpy(cookie->contents, otp_challenge.nonce.data,
           otp_challenge.nonce.length);

    /* Encode challenge.  */
    retval = encode_krb5_pa_otp_challenge(&otp_challenge,
                                          &encoded_otp_challenge);
    if (retval != 0) {
        SERVER_DEBUG("encode_krb5_pa_otp_challenge failed.");
        goto errout;
    }

    pa_data->pa_type = KRB5_PADATA_OTP_CHALLENGE;
    pa_data->contents = (krb5_octet *) encoded_otp_challenge->data;
    pa_data->length = encoded_otp_challenge->length;
    return 0;

 errout:
    krb5_free_keyblock(context, armor_key);
    free(otp_challenge.nonce.data);
    if (cookie != NULL) {
        free(cookie->contents);
    }
    return retval;
}

static krb5_error_code
server_verify_preauth(krb5_context context,
                      struct _krb5_db_entry_new *client,
                      krb5_data *req_pkt,
                      krb5_kdc_req *request,
                      krb5_enc_tkt_part *enc_tkt_reply,
                      krb5_pa_data *data,
                      const krb5_pa_data *cookie,
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
    krb5_tl_data *tl_data;
    char *blob = NULL;
    int f;

    assert(otp_ctx != NULL);

    /* Decode PA-OTP-REQUEST in pa-data.  */
    encoded_otp_req.length = data->length;
    encoded_otp_req.data = (char *) data->contents;
    retval = decode_krb5_pa_otp_req(&encoded_otp_req, &otp_req);
    if (retval != 0) {
        SERVER_DEBUG("Decoding OTP request failed.");
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        goto errout;
    }

    /* Decrypt PA-OTP-REQUEST encData containing the server nonce from
       the KRB-ERROR message in 4-pass mode (PA-OTP-ENC-REQUEST) or a
       timestamp (PA-ENC-TS-ENC) in 2-pass mode.  */
    if (otp_req->enc_data.ciphertext.data == NULL) {
        SERVER_DEBUG("Missing PA-OTP-REQUEST encData.");
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        goto errout;
    }

    decrypted_data.length = otp_req->enc_data.ciphertext.length;
    decrypted_data.data = (char *) malloc(decrypted_data.length);
    if (decrypted_data.data == NULL) {
        retval = ENOMEM;
        goto errout;
    }

    retval = fast_kdc_get_armor_key(context, server_get_entry_data, request,
                                    client, &armor_key);
    if (retval != 0) {
        SERVER_DEBUG("%s: Unable to get armor key.", __func__);
        goto errout;
    }

    /* FIXME: Find out if encData is nonce or timestamp and decode:
   PA-OTP-ENC-REQUEST ::= SEQUENCE {
           nonce     [0] OCTET STRING,
           ...
   }
   PA-ENC-TS-ENC           ::= SEQUENCE {
           patimestamp     [0] KerberosTime -- client's time --,
           pausec          [1] Microseconds OPTIONAL
   }
    */
    retval = krb5_c_decrypt(context, armor_key, KRB5_KEYUSAGE_PA_OTP_REQUEST,
                            NULL, &otp_req->enc_data, &decrypted_data);
    if (retval != 0) {
        SERVER_DEBUG("%s: Unable to decrypt PA-OTP-REQUEST encData.", __func__);
        goto errout;
    }

    /* Verify nonce against cookie in pa-data.  */
    if (cookie == NULL) {
        SERVER_DEBUG("Missing cookie.");
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        goto errout;
    }
    if (decrypted_data.length != cookie->length
        ||memcmp(decrypted_data.data, cookie->contents, cookie->length)) {
        SERVER_DEBUG("Bad nonce in request.");
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        goto errout;
    }
    SERVER_DEBUG("Nonce in PA-OTP-REQUEST matches contents of PA-FX-COOKIE.");

    krb5_free_data_contents(context, &decrypted_data);
    SERVER_DEBUG("OTP (%.*s)", otp_req->otp_value.length,
                 otp_req->otp_value.data);
    otp = strndup(otp_req->otp_value.data, otp_req->otp_value.length);
    if (otp == NULL) {
        SERVER_DEBUG("strndup failed.");
        retval = ENOMEM;
        goto errout;
    }

    tl_data = client->tl_data;
    while (tl_data != NULL) {
        int found_flag = 0;
        if (tl_data->tl_data_type == KRB5_TL_OTP_BLOB) {
            free(blob);
            blob = calloc(1, tl_data->tl_data_length);
            if (blob == NULL) {
                retval = ENOMEM;
                goto errout;
            }
            memcpy(blob, tl_data->tl_data_contents, tl_data->tl_data_length);
            for (f = 0; f < tl_data->tl_data_length; f++) {
                if (blob[f] == ':') {
                    blob[f] = '\0';
                    if (strcmp(blob, otp_ctx->token_id) == 0) {
                        found_flag = 1;
                        otp_ctx->blob = blob + f + 1;
                        otp_ctx->blobsize = tl_data->tl_data_length - f - 1;
                        break;
                    }
                }
            }
        }
        if (found_flag) {
            break;
        }
        tl_data = tl_data->tl_data_next;
    }

    assert(otp_ctx->method->ftable != NULL);
    assert(otp_ctx->method->ftable->server_verify != NULL);
    ret = otp_ctx->method->ftable->server_verify(otp_ctx, otp);
    free(otp);

    if (ret != 0) {
        SERVER_DEBUG("OTP verification failed with %d.", ret);
        *pa_request_context = NULL; /* FIXME: Really touch context
                                       here and only here in the error
                                       path? */
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        goto errout;
    }

    *pa_request_context = armor_key;
    enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;
    enc_tkt_reply->flags |= TKT_FLG_HW_AUTH;

    SERVER_DEBUG("OTP verification succeeded for [%s].", otp_ctx->token_id);
    return 0;

 errout:
    krb5_free_data_contents(context, &decrypted_data);
    if (armor_key != NULL) {
        krb5_free_keyblock(context, armor_key);
    }
    return retval;
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
