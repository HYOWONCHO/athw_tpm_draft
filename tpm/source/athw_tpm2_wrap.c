/********************************************************************************
 * Copyright (C) 2020 by Trustkey                                               * 
 * This file is part of  Project                                                *   
 * This software contains confidential information of TrustKey Co.,Ltd.         *
 * and unauthorized distribution of this software, or any portion of it, are    *
 * prohibited.                                                                  *
 ********************************************************************************/

/**
 * @file athw_tpm2_wrap.c
 * TPM operation wrapper function
 *
 * @anchor LEON_SYSTEM
 * @author Leon, (c) Trustkey
 * @version Draft 
 * @date 2023-10-26
 * @bug No known bugs.
 * @note 
 * 
 * @copyright Copyright 2020 Trustkey. All rights reserved*
 */

#include "tpm_common.h"
#include "athw_tpm_wrap.h"
#include "tpm2.h"
#include "tpm_io.h"

static void athw_tpm_copy_symmetric(TPMT_SYM_DEF* out, const TPMT_SYM_DEF* in);

static void athw_tpm_copy_pubt(TPMT_PUBLIC* out, const TPMT_PUBLIC* in)
{
    if (out == NULL || in == NULL)
        return;

    out->type = in->type;
    out->nameAlg = in->nameAlg;
    out->objectAttributes = in->objectAttributes;
    out->authPolicy.size = in->authPolicy.size;
    if (out->authPolicy.size > 0) {
        if (out->authPolicy.size >
                (UINT16)sizeof(out->authPolicy.buffer))
            out->authPolicy.size =
                (UINT16)sizeof(out->authPolicy.buffer);
        memcpy(out->authPolicy.buffer,
                in->authPolicy.buffer,
                out->authPolicy.size);
    }

    switch (out->type) {
    case TPM_ALG_KEYEDHASH:
        out->parameters.keyedHashDetail.scheme =
            in->parameters.keyedHashDetail.scheme;

        out->unique.keyedHash.size =
            in->unique.keyedHash.size;
        if (out->unique.keyedHash.size >
                (UINT16)sizeof(out->unique.keyedHash.buffer)) {
            out->unique.keyedHash.size =
                (UINT16)sizeof(out->unique.keyedHash.buffer);
        }
        memcpy(out->unique.keyedHash.buffer,
                in->unique.keyedHash.buffer,
                out->unique.keyedHash.size);
        break;
    case TPM_ALG_SYMCIPHER:
        out->parameters.symDetail.sym.algorithm =
            in->parameters.symDetail.sym.algorithm;
        out->parameters.symDetail.sym.keyBits.sym =
            in->parameters.symDetail.sym.keyBits.sym;
        out->parameters.symDetail.sym.mode.sym =
            in->parameters.symDetail.sym.mode.sym;

        out->unique.sym.size =
            in->unique.sym.size;
        if (out->unique.sym.size >
                (UINT16)sizeof(out->unique.sym.buffer)) {
            out->unique.sym.size =
                (UINT16)sizeof(out->unique.sym.buffer);
        }
        memcpy(out->unique.sym.buffer,
                in->unique.sym.buffer,
                out->unique.sym.size);
        break;
//  case TPM_ALG_RSA:
//      athw_tpm_copy_symmetric(&out->parameters.rsaDetail.symmetric,
//          &in->parameters.rsaDetail.symmetric);
//      out->parameters.rsaDetail.scheme.scheme =
//          in->parameters.rsaDetail.scheme.scheme;
//      if (out->parameters.rsaDetail.scheme.scheme != TPM_ALG_NULL)
//          out->parameters.rsaDetail.scheme.details.anySig.hashAlg =
//              in->parameters.rsaDetail.scheme.details.anySig.hashAlg;
//      out->parameters.rsaDetail.keyBits =
//          in->parameters.rsaDetail.keyBits;
//      out->parameters.rsaDetail.exponent =
//          in->parameters.rsaDetail.exponent;
//
//      out->unique.rsa.size =
//          in->unique.rsa.size;
//      if (out->unique.rsa.size >
//              (UINT16)sizeof(out->unique.rsa.buffer)) {
//          out->unique.rsa.size =
//              (UINT16)sizeof(out->unique.rsa.buffer);
//      }
//      memcpy(out->unique.rsa.buffer,
//              in->unique.rsa.buffer,
//              out->unique.rsa.size);
//      break;
//  case TPM_ALG_ECC:
//      athw_tpm_copy_symmetric(&out->parameters.eccDetail.symmetric,
//          &in->parameters.eccDetail.symmetric);
//      out->parameters.eccDetail.scheme.scheme =
//          in->parameters.eccDetail.scheme.scheme;
//      if (out->parameters.eccDetail.scheme.scheme != TPM_ALG_NULL) {
//          out->parameters.eccDetail.scheme.details.any.hashAlg =
//              in->parameters.eccDetail.scheme.details.any.hashAlg;
//      }
//      out->parameters.eccDetail.curveID =
//          in->parameters.eccDetail.curveID;
//      out->parameters.eccDetail.kdf.scheme =
//          in->parameters.eccDetail.kdf.scheme;
//      if (out->parameters.eccDetail.kdf.scheme != TPM_ALG_NULL) {
//          out->parameters.eccDetail.kdf.details.any.hashAlg =
//              in->parameters.eccDetail.kdf.details.any.hashAlg;
//      }
//      wolfTPM2_CopyEccParam(&out->unique.ecc.x,
//          &in->unique.ecc.x);
//      wolfTPM2_CopyEccParam(&out->unique.ecc.y,
//          &in->unique.ecc.y);
//      break;
    default:
        athw_tpm_copy_symmetric(&out->parameters.asymDetail.symmetric,
            &in->parameters.asymDetail.symmetric);
        out->parameters.asymDetail.scheme.scheme =
            in->parameters.asymDetail.scheme.scheme;
        if (out->parameters.asymDetail.scheme.scheme != TPM_ALG_NULL)
            out->parameters.asymDetail.scheme.details.anySig.hashAlg =
                in->parameters.asymDetail.scheme.details.anySig.hashAlg;
        break;
    }
}

static void athw_tpm_copy_pub(TPM2B_PUBLIC* out, const TPM2B_PUBLIC* in)
{
    if( out != NULL && in != NULL ) {
        out->size = in->size;
        athw_tpm_copy_pubt(&out->publicArea, &in->publicArea);
    }
}

static void athw_tpm_copy_priv(TPM2B_PRIVATE* out, const TPM2B_PRIVATE* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        if (out->size > (UINT16)sizeof(out->buffer))
            out->size = (UINT16)sizeof(out->buffer);
        memcpy(out->buffer, in->buffer, out->size);
    }
}


static void athw_tpm_copyname(TPM2B_NAME* out, const TPM2B_NAME* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        if (out->size > (UINT16)sizeof(out->name))
            out->size = (UINT16)sizeof(out->name);
        memcpy(out->name, in->name, out->size);
    }
}

static void athw_tpm_copyauth(TPM2B_AUTH* out, const TPM2B_AUTH* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        if (out->size > (UINT16)sizeof(out->buffer))
            out->size = (UINT16)sizeof(out->buffer);
        memcpy(out->buffer, in->buffer, out->size);
    }
}


static void athw_tpm_copy_symmetric(TPMT_SYM_DEF* out, const TPMT_SYM_DEF* in)
{
    if (out == NULL || in == NULL)
        return;

    out->algorithm = in->algorithm;
    switch (out->algorithm) {
        case TPM_ALG_XOR:
            out->keyBits.xorr = in->keyBits.xorr;
            break;
        case TPM_ALG_AES:
            out->keyBits.aes = in->keyBits.aes;
            out->mode.aes = in->mode.aes;
            break;
        case TPM_ALG_NULL:
            break;
        default:
            out->keyBits.sym = in->keyBits.sym;
            out->mode.sym = in->mode.sym;
            break;
    }
}


static int  athw_tpm_init_ex(void *ctx, void *iocb, void *userctx, int timeouttries)
{
    int rc = ATHW_EOK;
    TPM2_CTX *h = NULL;
    Startup_In  startupin;
#if defined(ATHW_PERFORM_SELFTEST)
    SelfTest_In     selftest;
#endif
    //SelfTest_In selfTest;
    
    if( ctx == NULL ) {
        tr_log("Context handle NULL");
        return -ATHW_ENULLP;
    }
    
    h = (TPM2_CTX *)ctx;
    rc = TPM2_Init_ex(h, (TPM2HalIoCb)iocb, userctx, timeouttries);
    if( rc  != ATHW_EOK ) {
        tr_log("TPM device initialization fail %d: %s", rc, TPM2_GetRCString(rc));
        return rc;
    }
    
    printf("TPM2: Caps 0x%08x, Did 0x%04x, Vid 0x%04x, Rid 0x%2x \r\n",
        h->caps,
        h->did_vid >> 16,
        h->did_vid & 0xFFFF,
        h->rid);
    
    memset(&startupin, 0, sizeof startupin);
    startupin.startupType = TPM_SU_CLEAR;
    rc = TPM2_Startup(&startupin);
    
    if( rc != TPM_RC_SUCCESS && rc != TPM_RC_INITIALIZE) {
        tr_log("TPM2_Startup failed %d: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    
    tr_log("TPM2_Starup pass \n");
    
    // TO DO : Self Test
#if defined(ATHW_PERFORM_SELFTEST)
    tr_log("Enter the TPM2 Self Test ");
    memset(&selftest, 0, sizeof selftest);
    selftest.fullTest = YES;
    rc = TPM2_SelfTest(&selftest);
    if( rc != ATHW_EOK ) {
        tr_log("TPM2_SelfTest failed 0x%x: %s", rc, TPM2_GetRCString(rc));
        return rc;
    }
    
    tr_log("TPM2_SelfTest pass");

#endif    
    rc = TPM_RC_SUCCESS;
    
    return rc;
}

int athw_tpm_init(void *dev, void *iocb, void *userctx)
{
    int rc = ATHW_EOK;
    WOLFTPM2_DEV *h = NULL;
    
    if( dev == NULL ) {
        return -ATHW_ENULLP;
    }
    
    h = (WOLFTPM2_DEV *)dev;
    
    memset(h, 0, sizeof *h);
    
    rc = athw_tpm_init_ex(&h->ctx, iocb, userctx, 5);
    if( rc != TPM_RC_SUCCESS ) {
        return rc;
    }
    
    // TO DO : Define default session auth
    memset(h->session, 0, sizeof(h->session));
    athw_tpm_set_auth_password(dev, 0, NULL);
    
    return rc;
}


int athw_tpm_getrandom(void *dev, uint8_t *buf, uint32_t len)
{
    int rc = ATHW_EOK;
    
    GetRandom_In in;
    GetRandom_Out out;
    uint32_t sz, pos = 0;
        
    (void)dev;
    
    if( buf == NULL) {
        tr_log("Bad argument");
        rc = -ATHW_EINVAL;
        goto athw_wrap_release;
    }
    
    if( len <= 0 ) {
        tr_log("Length of zero");
        rc = -ATHW_ESZEROL;
        goto athw_wrap_release;
    }
    
    while(pos < len) {
        sz = len - pos;
        if( sz > MAX_RNG_REQ_SIZE ) {
            sz = MAX_RNG_REQ_SIZE;
        }
        
        memset(&in, 0 , sizeof in);
        in.bytesRequested = sz;
        
        rc = TPM2_GetRandom(&in, &out);
        if( rc != ATHW_EOK ) {
            tr_log("TPM GetRandom fail %d", rc);
            break;
        }
        
        sz = out.randomBytes.size;
        if( sz > MAX_RNG_REQ_SIZE ) {
            tr_log("TPM GetRandom out of size error");
            rc = -ATHW_EINVAL;
            goto athw_wrap_release;
        }
        
        memcpy(&buf[pos], out.randomBytes.buffer, sz);
        pos += sz;


    };
    
athw_wrap_release:
    
    return rc;
    
    
}

int athw_tpm_set_auth(void *_dev, int index, TPM_HANDLE session_handle,
                      const TPM2B_AUTH *auth,
                      TPMA_SESSION session_attr, 
                      const TPM2B_NAME *name)
{
    int rc = ATHW_EOK;
    TPM2_AUTH_SESSION *session;
    WOLFTPM2_DEV *dev = NULL;
    
    dev = (WOLFTPM2_DEV *)_dev;
        
    if( dev == NULL || index >= MAX_SESSION_NUM || index < 0 ) {
        rc = -ATHW_EINVAL;
        goto exit;
    }
    
    session = &dev->session[index];
    memset(session, 0, sizeof(TPM2_AUTH_SESSION));
    
    session->sessionHandle = session_handle;
    session->sessionAttributes = session_attr;
    
    if( auth ) {
        session->auth.size = auth->size;
        memcpy(session->auth.buffer, auth->buffer, auth->size);
    }
    
    if( name ) {
        session->name.size = name->size;
        memcpy(session->name.name, name->name, name->size);
    }
    
    TPM2_SetSessionAuth(dev->session);
    
exit:

    return rc;
}

int athw_tpm_set_auth_password(void *dev, int index, const TPM2B_AUTH *auth)
{
    return athw_tpm_set_auth(dev,index,TPM_RS_PW, auth, 0 , NULL);
}

int athw_tpm_set_auth_handle(void *_dev, int index, const athwtpm2_handle_t *handle)
{
    const TPM2B_AUTH *auth = NULL;
    const TPM2B_NAME *name = NULL;
    
    WOLFTPM2_DEV  *dev = (WOLFTPM2_DEV *)_dev;
    
    // do not set the auth for this policy session
    if( dev->ctx.session == NULL || handle->policyAuth  ) {
        return ATHW_EOK;
    }
    
    if( handle ) {
        auth = &handle->auth;
        name = &handle->name;
    }
    
    return athw_tpm_set_auth(_dev, index, TPM_RS_PW, auth, 0, name);

}

int athw_tpm_enc_dec_block(void *dev, athwtpm2_key_t *key, 
                           const uint8_t *in, uint8_t *out,uint8_t io_sz, 
                           uint8_t *iv, uint32_t iv_sz,
                           int is_decrypt) 
{
    int rc = ATHW_EOK;
    
    EncryptDecrypt2_In  cipher_in;
    EncryptDecrypt2_Out cipher_out;
    
    if( dev == NULL || key == NULL || in == NULL || out == NULL ) {
        rc = -ATHW_ENULLP;
        goto exit;
    }
    
    // set-up the session auth for key
    athw_tpm_set_auth_handle(dev, 0, &key->handle);
    
    memset(&cipher_in, 0, sizeof cipher_in);
    memset(&cipher_out, 0, sizeof cipher_out);  
    
    cipher_in.keyHandle = key->handle.hndl;
    
    if( iv == NULL || iv_sz == 0 ) {
        cipher_in.ivIn.size = MAX_AES_BLOCK_SIZE_BYTES;
    }
    else {
        cipher_in.ivIn.size = iv_sz;
        memcpy(cipher_in.ivIn.buffer, iv, iv_sz);
    }
    
    cipher_in.decrypt = is_decrypt;
    //use symmetric algorithm from key
    
    cipher_in.mode =  key->pub.publicArea.parameters.symDetail.sym.mode.aes;
    cipher_in.inData.size = io_sz;
    memcpy(cipher_in.inData.buffer, in, io_sz);

    // multiple block size
    cipher_in.inData.size = (cipher_in.inData.size + MAX_AES_BLOCK_SIZE_BYTES - 1) &
                                ~(MAX_AES_BLOCK_SIZE_BYTES - 1);
    
    rc = TPM2_EncryptDecrypt2(&cipher_in, &cipher_out); 
    if( rc == TPM_RC_COMMAND_CODE ) {
        rc = athw_tpm_set_command(dev, TPM_CC_EncryptDecrypt2, YES);
        if( rc == 0 ) {
            rc = TPM2_EncryptDecrypt2(&cipher_in, &cipher_out);
        }
    }

    if( rc != 0 ) {
        tr_log("TPM2 EncryptDecrypt2 failed 0x%x: %s", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    
    //if have iv, set-up the iv data
    if( iv ) {
        if( iv_sz < cipher_out.ivOut.size ) {
            iv_sz = cipher_out.ivOut.size;
        }
        
        memcpy(iv, cipher_out.ivOut.buffer, iv_sz);
    }
    
    // return the cipher result
    if( io_sz > cipher_out.outData.size ) {
        io_sz = cipher_out.outData.size;
    }

    memcpy(out, cipher_out.outData.buffer, io_sz);

    
    
exit:
    return rc;
    
}

int athw_tpm_set_command(void *dev, TPM_CC command_code, int flag)
{
    int rc = TPM_RC_COMMAND_CODE;
    
#if defined(TPM_ST33)
    SetCommandSet_In in;
    if( TPM2_GetVendorID() == TPM_VENDOR_STM ) {
        memset(&in, 0, sizeof(in));
        in.authHandle = TPM_RH_PLATFORM;
        in.commandCode = command_code;
        in.enableFlag = flag;
        
        rc = TPM2_SetCommandSet(&in);
        if( rc != TPM_RC_SUCCESS ) {
            tr_log("TPM2_SetCommandSet fail 0x%d: %s",
                   rc, TPM2_GetRCString(rc));
        }

        
        
    }
#else
    (void)command_code;
    (void)flag;
#endif
    (void)dev;
    return rc;
    
    
}


int athw_tpm_encrypt_decrypt(void *dev, athwtpm2_key_t *key, const uint8_t *in,
                             uint8_t *out, uint32_t io_sz,
                             uint8_t *iv, uint32_t iv_sz, int is_decrypt)
{
    int rc = ATHW_EOK;
    uint32_t pos = 0, xfer = 0;
    
    if( dev == NULL && key == NULL ) {
        rc = -ATHW_ENULLP;
        goto exit;
    }
    
    while( pos < io_sz ) {
        xfer = io_sz - pos;
        if( xfer > MAX_DIGEST_BUFFER ) {
            xfer = MAX_DIGEST_BUFFER;
        }
        
        rc = athw_tpm_enc_dec_block(dev, key, &in[pos], &out[pos], xfer, iv, iv_sz,
                                    is_decrypt);
        
        if( rc != ATHW_EOK ) {
            break;
        }
        
        pos += xfer;
    }
    
    tr_log("TPM encrypt/decrypt: 0x%x: %s %d bytes", rc, TPM2_GetRCString(rc), io_sz);
    

exit:
    
    return rc;
}

int athw_tpm_self_test(void *_dev)
{
    int rc = ATHW_EOK;
    SelfTest_In  test;
    
    WOLFTPM2_DEV *dev = (WOLFTPM2_DEV *)_dev;
    
    if( dev == NULL ) {
        return -ATHW_ENULLP;
    }
    
    memset(&test, 0, sizeof test);
    test.fullTest = YES;
    rc = TPM2_SelfTest(&test);
    
    if( rc != ATHW_EOK ) {
        tr_log("TPM2_SelfTest failed 0x%x: %s \n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    
    tr_log("TPM2_SelfTest pass \n");
    return rc;
}

int athw_get_key_template_symmetric(TPMT_PUBLIC *key, int keybits, TPM_ALG_ID mode, 
                                    int is_sign, int is_decrypt)
{
    if( key == NULL ) {
        return -ATHW_ENULLP;
    }
    
    memset(key, 0, sizeof *key);
    key->type = TPM_ALG_SYMCIPHER;
    key->nameAlg = TPM_ALG_SHA256;
    key->unique.sym.size = keybits >> 3; //keybits / 8    
    key->objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA | (is_sign ? TPMA_OBJECT_sign : 0) |
        (is_decrypt ? TPMA_OBJECT_decrypt : 0));
    
    key->parameters.symDetail.sym.algorithm = TPM_ALG_AES;
    key->parameters.symDetail.sym.keyBits.sym = keybits;
    key->parameters.symDetail.sym.mode.sym = mode;
    
    return ATHW_EOK;  
}

int athw_tpm_createkey(void *handle, const uint8_t *auth, int authsz)
{
    int rc;
    athwtpm2_keyhnd_t   *h = NULL;
    Create_In       inkey;
    Create_Out      outkey;
    
    if( handle == NULL ) {
        return -ATHW_ENULLP;
    }
    h = (athwtpm2_keyhnd_t *)handle;
    
    athw_memzero_s(h->blob, sizeof *h->blob);
    athw_memzero_s(&outkey, sizeof outkey);
    
    athw_tpm_set_auth_handle(h->dev, 0, h->parent);
    
    athw_memzero_s(&inkey, sizeof inkey);
    inkey.parentHandle = h->parent->hndl;
    
    if( auth ) {
        inkey.inSensitive.sensitive.userAuth.size = authsz;
        memcpy(inkey.inSensitive.sensitive.userAuth.buffer, 
                auth,
                inkey.inSensitive.sensitive.userAuth.size);

    }
    
    memcpy(&inkey.inPublic.publicArea, h->pub, sizeof *h->pub);
    rc = TPM2_Create(&inkey, &outkey);
    if( rc != 0 ) {
        //tr_log("TPM2_Create key fail (0x%x) : %s", rc, TPM2_GetRCString(rc));
        return rc;
    }
#ifdef  ATHW_DEBUG_TPM
    printf("tpm2 creation key: pub %d, priv %d \r\n",
        outkey.outPublic.size, outkey.outPrivate.size);
    TPM2_PrintPublicArea(&outkey.outPublic); 
#endif

    athw_tpm_copyauth(&h->blob->handle.auth, &inkey.inSensitive.sensitive.userAuth);
    athw_tpm_copy_symmetric(&h->blob->handle.symmetric, 
                            &outkey.outPublic.publicArea.parameters.asymDetail.symmetric);
    athw_tpm_copy_pub(&h->blob->pub, &outkey.outPublic);
    athw_tpm_copy_priv(&h->blob->priv, &outkey.outPrivate);
    
    return rc;
    
}

int athw_tpm_loadkey(void *handle)
{
    int rc;
    Load_In     inload;
    Load_Out    outload;
    athwtpm2_keyhnd_t *h = NULL;
    
    h = (athwtpm2_keyhnd_t *)handle; 
    
    athw_tpm_set_auth_handle(h->dev, 0, h->parent);
    
    // new key load
    athw_memzero_s(&inload, sizeof inload);
    inload.parentHandle = h->parent->hndl;
    athw_tpm_copy_priv(&inload.inPrivate, &h->blob->priv);
    athw_tpm_copy_pub(&inload.inPublic, &h->blob->pub);
    
    rc = TPM2_Load(&inload, &outload);
    if( rc != 0 ) {
        tr_log("Key load fail (%d)-(%s)", rc, TPM2_GetRCString(rc));
        return rc;
    }
    
    h->blob->handle.hndl = outload.objectHandle;
    athw_tpm_copyname(&h->blob->handle.name, &outload.name);
    
    
#ifdef ATHW_DEBUG_TPM
    tr_log("Loaded Key handle 0x%x", (uint32_t)h->blob->handle.hndl);
#endif
    
    
    return rc;

    
    
    
    
    
}


int athw_tpm_create_and_load_key(void *handle, const uint8_t *auth, int authsz)
{
    int rc;
    athwtpm2_keyblob_t keyblob;
    athwtpm2_keyhnd_t   *h = (athwtpm2_keyhnd_t *)handle;
    if( handle == NULL  ) {
        return -ATHW_ENULLP;
    }
    
    
    h->blob = &keyblob;
    athw_memzero_s(h->blob, sizeof *h->blob);
    rc = athw_tpm_createkey(handle, auth, authsz);
    
    if( rc != 0 ) {
        goto exit; 
    }
    
    rc =  athw_tpm_loadkey(handle);
    
exit:
    
    memcpy(h->key, &keyblob, h->parent);

    return rc;
    

}
    

int athw_tpm_start_session(void *dev, TPM_SE type, int cipheralg)
{
    int rc;
    StartAuthSession_In insession;
    StartAuthSession_Out outsession;
    
    athwtpm2_sessionhndl_t *session = (athwtpm2_sessionhndl_t *)dev;
    
    TPM2B_AUTH *bindauth = NULL;
    TPM2B_DATA keyin;
    TPMI_ALG_HASH hashauth  =   TPM_ALG_SHA256;
    int sz_digest = 0L;
    
    
    if (session == NULL || session->dev  == NULL || session->session) {
        return -ATHW_ENULLP;
    }
    
    athw_memzero_s(session->session, sizeof *session->session);
    athw_memzero_s(&insession, sizeof insession);
    
    insession.authHash = hashauth;
    sz_digest = TPM2_GetHashDigestSize(hashauth);
    if (sz_digest <= 0) {
        return -ATHW_EINVAL;
    }
    
    
    // set session auth for key
    if (session->key) {
        TPMA_SESSION attrsession = 0;
        
        if (cipheralg == TPM_ALG_CFB || cipheralg == TPM_ALG_XOR) {
            attrsession |=  (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt);
        }
        
        athw_tpm_set_auth(session->dev, session->key->handle.hndl,
                          &session->key->handle.auth,
                          attrsession, NULL);
        insession.tpmKey = session->key->handle.hndl;
    }
    else {
        athw_tpm_set_auth_password(session->dev, 0, NULL);
        insession.tpmKey = (TPMI_DH_OBJECT)TPM_RH_NULL;
    }
    
    // bind-key setup
    insession.bind = (TPMI_DH_ENTITY)TPM_RH_NULL;
    if (session->bindhndl) {
        insession.bind = session->bindhndl;
        bindauth = &session->bindhndl->auth;
    }
    
    insession.sessionType = type;
    if (cipheralg == TPM_ALG_CFB) {
        insession.symmetric.algorithm = TPM_ALG_AES;
        insession.symmetric.keyBits.aes = 128;
        insession.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else if (cipheralg == TPM_ALG_XOR) {
        insession.symmetric.algorithm = TPM_ALG_XOR;
        insession.symmetric.keyBits.xorr = TPM_ALG_SHA256;
        insession.symmetric.mode.sym = TPM_ALG_NULL;
    }
    else {
        insession.symmetric.algorithm = TPM_ALG_NULL;
    }   
    
    insession.nonceCaller.size = sz_digest; 
    
    rc = TPM2_GetNonce(insession.nonceCaller.buffer, insession.nonceCaller.size);
    if (rc < 0) {
        tr_log("TPM2_GetNonde failed (0x%x) - %s", rc, TPM2_GetRCString(rc));
        return rc;
    }
    
    if (insession.tpmKey != TPM_RH_NULL) {
        session->session->salt.size = sz_digest;
        rc = TPM2_GetNonce(session->session->salt.buffer, session->session->salt.size);
        if (rc != 0) {
            tr_log("TPM2_GetNonde failed (0x%x) - %s", rc, TPM2_GetRCString(rc));
            return rc;
        }
        
//      if (session->dev == NULL || session->key || &session->session->salt == NULL) {
//      }

        // Encrypt salt
    }
    
    rc = TPM2_StartAuthSession(&insession, &outsession);
    if (rc != 0) {
        tr_log("TPM2_StartAuthSession failed (%d) - %s", rc, TPM2_GetRCString(rc));
        return rc;
    }
}



