#include "internal/cryptlib.h"
#ifndef OPENSSL_NO_SAIFERV12
# include <openssl/evp.h>
# include <openssl/modes.h>
# include <openssl/rand.h>
# include <openssl/rand_drbg.h>
# include "crypto/saiferv12.h"
# include "crypto/evp.h"
# include "crypto/modes/modes_local.h"
# include "evp_local.h"


typedef struct {
    SAIFERV12_KEY ks;
} EVP_SAIFERV12_KEY;


typedef struct {
    union {
        double align;
        SAIFERV12_KEY ks;
    } ks;                       
    int key_set;                
    int iv_set;                 
    GCM128_CONTEXT gcm;
    unsigned char *iv;          
    int ivlen;                  
    int taglen;
    int iv_gen;                 
    int tls_aad_len;            
} EVP_SAIFERV12_GCM_CTX;


typedef struct {
    union {
        double align;
        SAIFERV12_KEY ks;
    } ks;                       
    int key_set;                
    int iv_set;                 
    int tag_set;                
    int len_set;                
    int L, M;                   
    int tls_aad_len;            
    CCM128_CONTEXT ccm;
    ccm128_f str;
} EVP_SAIFERV12_CCM_CTX;


static int saiferv12_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    int ret;
    int mode = EVP_CIPHER_CTX_mode(ctx);

    if (enc || (mode != EVP_CIPH_ECB_MODE && mode != EVP_CIPH_CBC_MODE))
        ret = saiferv12_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                        EVP_CIPHER_CTX_get_cipher_data(ctx));
    else
        ret = saiferv12_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                        EVP_CIPHER_CTX_get_cipher_data(ctx));
    if (ret < 0) {
        EVPerr(EVP_F_SAIFERV12_INIT_KEY,EVP_R_SAIFERV12_KEY_SETUP_FAILED);
        return 0;
    }
    return 1;
}

static void saiferv12_cbc_encrypt(const unsigned char *in, unsigned char *out,
                             size_t len, const SAIFERV12_KEY *key,
                             unsigned char *ivec, const int enc)
{

    if (enc)
        CRYPTO_cbc128_encrypt(in, out, len, key, ivec,
                              (block128_f) saiferv12_encrypt);
    else
        CRYPTO_cbc128_decrypt(in, out, len, key, ivec,
                              (block128_f) saiferv12_encrypt);
}

static void saiferv12_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                                size_t length, const SAIFERV12_KEY *key,
                                unsigned char *ivec, int *num, const int enc)
{

    CRYPTO_cfb128_encrypt(in, out, length, key, ivec, num, enc,
                          (block128_f) saiferv12_encrypt);
}

static void saiferv12_cfb1_encrypt(const unsigned char *in, unsigned char *out,
                              size_t length, const SAIFERV12_KEY *key,
                              unsigned char *ivec, int *num, const int enc)
{
    CRYPTO_cfb128_1_encrypt(in, out, length, key, ivec, num, enc,
                            (block128_f) saiferv12_encrypt);
}

static void saiferv12_cfb8_encrypt(const unsigned char *in, unsigned char *out,
                              size_t length, const SAIFERV12_KEY *key,
                              unsigned char *ivec, int *num, const int enc)
{
    CRYPTO_cfb128_8_encrypt(in, out, length, key, ivec, num, enc,
                            (block128_f) saiferv12_encrypt);
}

static void saiferv12_ecb_encrypt(const unsigned char *in, unsigned char *out,
                             const SAIFERV12_KEY *key, const int enc)
{
    saiferv12_encrypt(in, out, key);
}

static void saiferv12_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                             size_t length, const SAIFERV12_KEY *key,
                             unsigned char *ivec, int *num)
{
    CRYPTO_ofb128_encrypt(in, out, length, key, ivec, num,
                         (block128_f) saiferv12_encrypt);
}

IMPLEMENT_BLOCK_CIPHER(saiferv12_128, ks, saiferv12, EVP_SAIFERV12_KEY,
                        NID_saiferv12_128, 16, 16, 16, 128,
                        0, saiferv12_init_key, NULL,
                        EVP_CIPHER_set_asn1_iv,
                        EVP_CIPHER_get_asn1_iv,
                        NULL)
IMPLEMENT_BLOCK_CIPHER(saiferv12_192, ks, saiferv12, EVP_SAIFERV12_KEY,
                        NID_saiferv12_192, 16, 24, 16, 128,
                        0, saiferv12_init_key, NULL,
                        EVP_CIPHER_set_asn1_iv,
                        EVP_CIPHER_get_asn1_iv,
                        NULL)
IMPLEMENT_BLOCK_CIPHER(saiferv12_256, ks, saiferv12, EVP_SAIFERV12_KEY,
                        NID_saiferv12_256, 16, 32, 16, 128,
                        0, saiferv12_init_key, NULL,
                        EVP_CIPHER_set_asn1_iv,
                        EVP_CIPHER_get_asn1_iv,
                        NULL)

# define IMPLEMENT_SAIFERV12_CFBR(ksize,cbits) \
                IMPLEMENT_CFBR(saiferv12,saiferv12,EVP_SAIFERV12_KEY,ks,ksize,cbits,16,0)
IMPLEMENT_SAIFERV12_CFBR(128,1)
IMPLEMENT_SAIFERV12_CFBR(192,1)
IMPLEMENT_SAIFERV12_CFBR(256,1)
IMPLEMENT_SAIFERV12_CFBR(128,8)
IMPLEMENT_SAIFERV12_CFBR(192,8)
IMPLEMENT_SAIFERV12_CFBR(256,8)

# define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER saiferv12_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        saiferv12_init_key,                  \
        saiferv12_##mode##_cipher,           \
        NULL,                           \
        sizeof(EVP_SAIFERV12_KEY),           \
        NULL,NULL,NULL,NULL };          \
const EVP_CIPHER *EVP_saiferv12_##keylen##_##mode(void) \
{ return &saiferv12_##keylen##_##mode; }

static int saiferv12_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    unsigned int num = EVP_CIPHER_CTX_num(ctx);
    EVP_SAIFERV12_KEY *dat = EVP_C_DATA(EVP_SAIFERV12_KEY,ctx);

    CRYPTO_ctr128_encrypt(in, out, len, &dat->ks,
                          EVP_CIPHER_CTX_iv_noconst(ctx),
                          EVP_CIPHER_CTX_buf_noconst(ctx), &num,
                          (block128_f) saiferv12_encrypt);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

BLOCK_CIPHER_generic(NID_saiferv12, 128, 1, 16, ctr, ctr, CTR, 0)
BLOCK_CIPHER_generic(NID_saiferv12, 192, 1, 16, ctr, ctr, CTR, 0)
BLOCK_CIPHER_generic(NID_saiferv12, 256, 1, 16, ctr, ctr, CTR, 0)




static void ctr64_inc(unsigned char *counter)
{
    int n = 8;
    unsigned char c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}

static int saiferv12_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                 const unsigned char *iv, int enc)
{
    int ret;
    EVP_SAIFERV12_GCM_CTX *gctx = EVP_C_DATA(EVP_SAIFERV12_GCM_CTX,ctx);

    if (!iv && !key)
        return 1;
    if (key) {
        ret = saiferv12_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                   &gctx->ks.ks);
        CRYPTO_gcm128_init(&gctx->gcm, &gctx->ks,
                           (block128_f) saiferv12_encrypt);
        if (ret < 0) {
            EVPerr(EVP_F_SAIFERV12_GCM_INIT_KEY,EVP_R_SAIFERV12_KEY_SETUP_FAILED);
            return 0;
        }

        if (iv == NULL && gctx->iv_set)
            iv = gctx->iv;
        if (iv) {
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
            gctx->iv_set = 1;
        }
        gctx->key_set = 1;
    } else {

        if (gctx->key_set)
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
        else
            memcpy(gctx->iv, iv, gctx->ivlen);
        gctx->iv_set = 1;
        gctx->iv_gen = 0;
    }
    return 1;
}

static int saiferv12_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    EVP_SAIFERV12_GCM_CTX *gctx = EVP_C_DATA(EVP_SAIFERV12_GCM_CTX,c);

    switch (type) {
    case EVP_CTRL_INIT:
        gctx->key_set = 0;
        gctx->iv_set = 0;
        gctx->ivlen = EVP_CIPHER_iv_length(c->cipher);
        gctx->iv = EVP_CIPHER_CTX_iv_noconst(c);
        gctx->taglen = -1;
        gctx->iv_gen = 0;
        gctx->tls_aad_len = -1;
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        if (arg <= 0)
            return 0;

        if ((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen)) {
            if (gctx->iv != EVP_CIPHER_CTX_iv_noconst(c))
                OPENSSL_free(gctx->iv);
            if ((gctx->iv = OPENSSL_malloc(arg)) == NULL) {
                EVPerr(EVP_F_SAIFERV12_GCM_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }
        gctx->ivlen = arg;
        return 1;

    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = gctx->ivlen;
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if (arg <= 0 || arg > 16 || EVP_CIPHER_CTX_encrypting(c))
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
        gctx->taglen = arg;
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (arg <= 0 || arg > 16 || !EVP_CIPHER_CTX_encrypting(c)
            || gctx->taglen < 0)
            return 0;
        memcpy(ptr, EVP_CIPHER_CTX_buf_noconst(c), arg);
        return 1;

    case EVP_CTRL_GCM_SET_IV_FIXED:

        if (arg == -1) {
            memcpy(gctx->iv, ptr, gctx->ivlen);
            gctx->iv_gen = 1;
            return 1;
        }
        if ((arg < 4) || (gctx->ivlen - arg) < 8)
            return 0;
        if (arg)
            memcpy(gctx->iv, ptr, arg);
        if (EVP_CIPHER_CTX_encrypting(c)
            && RAND_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0)
            return 0;
        gctx->iv_gen = 1;
        return 1;

    case EVP_CTRL_GCM_IV_GEN:
        if (gctx->iv_gen == 0 || gctx->key_set == 0)
            return 0;
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        if (arg <= 0 || arg > gctx->ivlen)
            arg = gctx->ivlen;
        memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
        ctr64_inc(gctx->iv + gctx->ivlen - 8);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_GCM_SET_IV_INV:
        if (gctx->iv_gen == 0 || gctx->key_set == 0
            || EVP_CIPHER_CTX_encrypting(c))
            return 0;
        memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:

        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
        gctx->tls_aad_len = arg;
        {
            unsigned int len =
                EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] << 8
                | EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];

            if (len < EVP_GCM_TLS_EXPLICIT_IV_LEN)
                return 0;
            len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;

            if (!EVP_CIPHER_CTX_encrypting(c)) {
                if (len < EVP_GCM_TLS_TAG_LEN)
                    return 0;
                len -= EVP_GCM_TLS_TAG_LEN;
            }
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] = len >> 8;
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 1] = len & 0xff;
        }

        return EVP_GCM_TLS_TAG_LEN;

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            EVP_SAIFERV12_GCM_CTX *gctx_out = EVP_C_DATA(EVP_SAIFERV12_GCM_CTX,out);
            if (gctx->gcm.key) {
                if (gctx->gcm.key != &gctx->ks)
                    return 0;
                gctx_out->gcm.key = &gctx_out->ks;
            }
            if (gctx->iv == EVP_CIPHER_CTX_iv_noconst(c))
                gctx_out->iv = EVP_CIPHER_CTX_iv_noconst(out);
            else {
                if ((gctx_out->iv = OPENSSL_malloc(gctx->ivlen)) == NULL) {
                    EVPerr(EVP_F_SAIFERV12_GCM_CTRL, ERR_R_MALLOC_FAILURE);
                    return 0;
                }
                memcpy(gctx_out->iv, gctx->iv, gctx->ivlen);
            }
            return 1;
        }

    default:
        return -1;

    }
}

static int saiferv12_gcm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len)
{
    EVP_SAIFERV12_GCM_CTX *gctx = EVP_C_DATA(EVP_SAIFERV12_GCM_CTX,ctx);
    int rv = -1;


    if (out != in
        || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN))
        return -1;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CIPHER_CTX_encrypting(ctx) ?
                            EVP_CTRL_GCM_IV_GEN : EVP_CTRL_GCM_SET_IV_INV,
                            EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0)
        goto err;

    if (CRYPTO_gcm128_aad(&gctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx),
                          gctx->tls_aad_len))
        goto err;

    in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    if (EVP_CIPHER_CTX_encrypting(ctx)) {

        if (CRYPTO_gcm128_encrypt(&gctx->gcm, in, out, len))
            goto err;
        out += len;

        CRYPTO_gcm128_tag(&gctx->gcm, out, EVP_GCM_TLS_TAG_LEN);
        rv = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    } else {

        if (CRYPTO_gcm128_decrypt(&gctx->gcm, in, out, len))
            goto err;

        CRYPTO_gcm128_tag(&gctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx),
                          EVP_GCM_TLS_TAG_LEN);

        if (CRYPTO_memcmp(EVP_CIPHER_CTX_buf_noconst(ctx), in + len,
                          EVP_GCM_TLS_TAG_LEN)) {
            OPENSSL_cleanse(out, len);
            goto err;
        }
        rv = len;
    }

 err:
    gctx->iv_set = 0;
    gctx->tls_aad_len = -1;
    return rv;
}

static int saiferv12_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_SAIFERV12_GCM_CTX *gctx = EVP_C_DATA(EVP_SAIFERV12_GCM_CTX,ctx);


    if (!gctx->key_set)
        return -1;

    if (gctx->tls_aad_len >= 0)
        return saiferv12_gcm_tls_cipher(ctx, out, in, len);

    if (!gctx->iv_set)
        return -1;
    if (in) {
        if (out == NULL) {
            if (CRYPTO_gcm128_aad(&gctx->gcm, in, len))
                return -1;
        } else if (EVP_CIPHER_CTX_encrypting(ctx)) {
            if (CRYPTO_gcm128_encrypt(&gctx->gcm, in, out, len))
                return -1;
        } else {
            if (CRYPTO_gcm128_decrypt(&gctx->gcm, in, out, len))
                return -1;
        }
        return len;
    }
    if (!EVP_CIPHER_CTX_encrypting(ctx)) {
        if (gctx->taglen < 0)
            return -1;
        if (CRYPTO_gcm128_finish(&gctx->gcm,
                                 EVP_CIPHER_CTX_buf_noconst(ctx),
                                 gctx->taglen) != 0)
            return -1;
        gctx->iv_set = 0;
        return 0;
    }
    CRYPTO_gcm128_tag(&gctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx), 16);
    gctx->taglen = 16;

    gctx->iv_set = 0;
    return 0;
}

static int saiferv12_gcm_cleanup(EVP_CIPHER_CTX *ctx)
{
    EVP_SAIFERV12_GCM_CTX *gctx = EVP_C_DATA(EVP_SAIFERV12_GCM_CTX, ctx);

    if (gctx->iv != EVP_CIPHER_CTX_iv_noconst(ctx))
        OPENSSL_free(gctx->iv);

    return 1;
}

static int saiferv12_ccm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    int ret;
    EVP_SAIFERV12_CCM_CTX *cctx = EVP_C_DATA(EVP_SAIFERV12_CCM_CTX,ctx);

    if (!iv && !key)
        return 1;

    if (key) {
        ret = saiferv12_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                   &cctx->ks.ks);
        CRYPTO_ccm128_init(&cctx->ccm, cctx->M, cctx->L,
                           &cctx->ks, (block128_f) saiferv12_encrypt);
        if (ret < 0) {
            EVPerr(EVP_F_SAIFERV12_CCM_INIT_KEY,EVP_R_SAIFERV12_KEY_SETUP_FAILED);
            return 0;
        }
        cctx->str = NULL;
        cctx->key_set = 1;
    }
    if (iv) {
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, 15 - cctx->L);
        cctx->iv_set = 1;
    }
    return 1;
}

static int saiferv12_ccm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    EVP_SAIFERV12_CCM_CTX *cctx = EVP_C_DATA(EVP_SAIFERV12_CCM_CTX,c);

    switch (type) {
    case EVP_CTRL_INIT:
        cctx->key_set = 0;
        cctx->iv_set = 0;
        cctx->L = 8;
        cctx->M = 12;
        cctx->tag_set = 0;
        cctx->len_set = 0;
        cctx->tls_aad_len = -1;
        return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:

        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
        cctx->tls_aad_len = arg;
        {
            uint16_t len =
                EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] << 8
                | EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];

            if (len < EVP_CCM_TLS_EXPLICIT_IV_LEN)
                return 0;
            len -= EVP_CCM_TLS_EXPLICIT_IV_LEN;

            if (!EVP_CIPHER_CTX_encrypting(c)) {
                if (len < cctx->M)
                    return 0;
                len -= cctx->M;
            }
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] = len >> 8;
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 1] = len & 0xff;
        }

        return cctx->M;

    case EVP_CTRL_CCM_SET_IV_FIXED:

        if (arg != EVP_CCM_TLS_FIXED_IV_LEN)
            return 0;

        memcpy(EVP_CIPHER_CTX_iv_noconst(c), ptr, arg);
        return 1;

    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = 15 - cctx->L;
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        arg = 15 - arg;

    case EVP_CTRL_CCM_SET_L:
        if (arg < 2 || arg > 8)
            return 0;
        cctx->L = arg;
        return 1;
    case EVP_CTRL_AEAD_SET_TAG:
        if ((arg & 1) || arg < 4 || arg > 16)
            return 0;
        if (EVP_CIPHER_CTX_encrypting(c) && ptr)
            return 0;
        if (ptr) {
            cctx->tag_set = 1;
            memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
        }
        cctx->M = arg;
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (!EVP_CIPHER_CTX_encrypting(c) || !cctx->tag_set)
            return 0;
        if (!CRYPTO_ccm128_tag(&cctx->ccm, ptr, (size_t)arg))
            return 0;
        cctx->tag_set = 0;
        cctx->iv_set = 0;
        cctx->len_set = 0;
        return 1;

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            EVP_SAIFERV12_CCM_CTX *cctx_out = EVP_C_DATA(EVP_SAIFERV12_CCM_CTX,out);
            if (cctx->ccm.key) {
                if (cctx->ccm.key != &cctx->ks)
                    return 0;
                cctx_out->ccm.key = &cctx_out->ks;
            }
            return 1;
        }

    default:
        return -1;
    }
}

static int saiferv12_ccm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len)
{
    EVP_SAIFERV12_CCM_CTX *cctx = EVP_C_DATA(EVP_SAIFERV12_CCM_CTX,ctx);
    CCM128_CONTEXT *ccm = &cctx->ccm;


    if (out != in || len < (EVP_CCM_TLS_EXPLICIT_IV_LEN + (size_t)cctx->M))
        return -1;

    if (EVP_CIPHER_CTX_encrypting(ctx))
        memcpy(out, EVP_CIPHER_CTX_buf_noconst(ctx),
               EVP_CCM_TLS_EXPLICIT_IV_LEN);

    memcpy(EVP_CIPHER_CTX_iv_noconst(ctx) + EVP_CCM_TLS_FIXED_IV_LEN, in,
           EVP_CCM_TLS_EXPLICIT_IV_LEN);

    len -= EVP_CCM_TLS_EXPLICIT_IV_LEN + cctx->M;
    if (CRYPTO_ccm128_setiv(ccm, EVP_CIPHER_CTX_iv_noconst(ctx), 15 - cctx->L,
                            len))
            return -1;

    CRYPTO_ccm128_aad(ccm, EVP_CIPHER_CTX_buf_noconst(ctx), cctx->tls_aad_len);

    in += EVP_CCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_CCM_TLS_EXPLICIT_IV_LEN;
    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        if (cctx->str ? CRYPTO_ccm128_encrypt_ccm64(ccm, in, out, len, cctx->str)
                      : CRYPTO_ccm128_encrypt(ccm, in, out, len))
            return -1;
        if (!CRYPTO_ccm128_tag(ccm, out + len, cctx->M))
            return -1;
        return len + EVP_CCM_TLS_EXPLICIT_IV_LEN + cctx->M;
    } else {
        if (cctx->str ? !CRYPTO_ccm128_decrypt_ccm64(ccm, in, out, len, cctx->str)
                      : !CRYPTO_ccm128_decrypt(ccm, in, out, len)) {
            unsigned char tag[16];
            if (CRYPTO_ccm128_tag(ccm, tag, cctx->M)) {
                if (!CRYPTO_memcmp(tag, in + len, cctx->M))
                    return len;
            }
        }
        OPENSSL_cleanse(out, len);
        return -1;
    }
}

static int saiferv12_ccm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_SAIFERV12_CCM_CTX *cctx = EVP_C_DATA(EVP_SAIFERV12_CCM_CTX,ctx);
    CCM128_CONTEXT *ccm = &cctx->ccm;


    if (!cctx->key_set)
        return -1;

    if (cctx->tls_aad_len >= 0)
        return saiferv12_ccm_tls_cipher(ctx, out, in, len);


    if (in == NULL && out != NULL)
        return 0;

    if (!cctx->iv_set)
        return -1;

    if (!out) {
        if (!in) {
            if (CRYPTO_ccm128_setiv(ccm, EVP_CIPHER_CTX_iv_noconst(ctx),
                                    15 - cctx->L, len))
                return -1;
            cctx->len_set = 1;
            return len;
        }

        if (!cctx->len_set && len)
            return -1;
        CRYPTO_ccm128_aad(ccm, in, len);
        return len;
    }


    if (!EVP_CIPHER_CTX_encrypting(ctx) && !cctx->tag_set)
        return -1;


    if (!cctx->len_set) {
        if (CRYPTO_ccm128_setiv(ccm, EVP_CIPHER_CTX_iv_noconst(ctx),
                                15 - cctx->L, len))
            return -1;
        cctx->len_set = 1;
    }
    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        if (cctx->str ? CRYPTO_ccm128_encrypt_ccm64(ccm, in, out, len, cctx->str)
                      : CRYPTO_ccm128_encrypt(ccm, in, out, len))
            return -1;
        cctx->tag_set = 1;
        return len;
    } else {
        int rv = -1;
        if (cctx->str ? !CRYPTO_ccm128_decrypt_ccm64(ccm, in, out, len,
                                                     cctx->str) :
            !CRYPTO_ccm128_decrypt(ccm, in, out, len)) {
            unsigned char tag[16];
            if (CRYPTO_ccm128_tag(ccm, tag, cctx->M)) {
                if (!CRYPTO_memcmp(tag, EVP_CIPHER_CTX_buf_noconst(ctx),
                                   cctx->M))
                    rv = len;
            }
        }
        if (rv == -1)
            OPENSSL_cleanse(out, len);
        cctx->iv_set = 0;
        cctx->tag_set = 0;
        cctx->len_set = 0;
        return rv;
    }
}

#define saiferv12_ccm_cleanup    NULL

#define SAIFERV12_AUTH_FLAGS  (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                          | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                          | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                          | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_FLAG_AEAD_CIPHER \
                          | EVP_CIPH_CUSTOM_IV_LENGTH)

#define BLOCK_CIPHER_aead(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER saiferv12_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,                  \
        blocksize, keylen/8, ivlen,                \
        SAIFERV12_AUTH_FLAGS|EVP_CIPH_##MODE##_MODE,    \
        saiferv12_##mode##_init_key,                    \
        saiferv12_##mode##_cipher,                      \
        saiferv12_##mode##_cleanup,                     \
        sizeof(EVP_SAIFERV12_##MODE##_CTX),             \
        NULL,NULL,saiferv12_##mode##_ctrl,NULL };       \
const EVP_CIPHER *EVP_saiferv12_##keylen##_##mode(void) \
{ return (EVP_CIPHER*)&saiferv12_##keylen##_##mode; }

BLOCK_CIPHER_aead(NID_saiferv12, 128, 1, 12, gcm, gcm, GCM, 0)
BLOCK_CIPHER_aead(NID_saiferv12, 192, 1, 12, gcm, gcm, GCM, 0)
BLOCK_CIPHER_aead(NID_saiferv12, 256, 1, 12, gcm, gcm, GCM, 0)

BLOCK_CIPHER_aead(NID_saiferv12, 128, 1, 12, ccm, ccm, CCM, 0)
BLOCK_CIPHER_aead(NID_saiferv12, 192, 1, 12, ccm, ccm, CCM, 0)
BLOCK_CIPHER_aead(NID_saiferv12, 256, 1, 12, ccm, ccm, CCM, 0)

#endif
