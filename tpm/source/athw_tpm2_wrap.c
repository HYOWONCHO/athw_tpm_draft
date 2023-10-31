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

static void ATHW_CopySymmetric(TPMT_SYM_DEF* out, const TPMT_SYM_DEF* in)
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

static void ATHW_CopyName(TPM2B_NAME* out, const TPM2B_NAME* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        if (out->size > (UINT16)sizeof(out->name))
            out->size = (UINT16)sizeof(out->name);
        XMEMCPY(out->name, in->name, out->size);
    }
}

static void ATHW_CopyAuth(TPM2B_AUTH* out, const TPM2B_AUTH* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        if (out->size > (UINT16)sizeof(out->buffer))
            out->size = (UINT16)sizeof(out->buffer);
        XMEMCPY(out->buffer, in->buffer, out->size);
    }
}

static void ATHW_CopyPubT(TPMT_PUBLIC* out, const TPMT_PUBLIC* in)
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
        XMEMCPY(out->authPolicy.buffer,
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
        XMEMCPY(out->unique.keyedHash.buffer,
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
        XMEMCPY(out->unique.sym.buffer,
                in->unique.sym.buffer,
                out->unique.sym.size);
        break;
    case TPM_ALG_RSA:
        ATHW_CopySymmetric(&out->parameters.rsaDetail.symmetric,
            &in->parameters.rsaDetail.symmetric);
        out->parameters.rsaDetail.scheme.scheme =
            in->parameters.rsaDetail.scheme.scheme;
        if (out->parameters.rsaDetail.scheme.scheme != TPM_ALG_NULL)
            out->parameters.rsaDetail.scheme.details.anySig.hashAlg =
                in->parameters.rsaDetail.scheme.details.anySig.hashAlg;
        out->parameters.rsaDetail.keyBits =
            in->parameters.rsaDetail.keyBits;
        out->parameters.rsaDetail.exponent =
            in->parameters.rsaDetail.exponent;

        out->unique.rsa.size =
            in->unique.rsa.size;
        if (out->unique.rsa.size >
                (UINT16)sizeof(out->unique.rsa.buffer)) {
            out->unique.rsa.size =
                (UINT16)sizeof(out->unique.rsa.buffer);
        }
        XMEMCPY(out->unique.rsa.buffer,
                in->unique.rsa.buffer,
                out->unique.rsa.size);
        break;
    case TPM_ALG_ECC:
        ATHW_CopySymmetric(&out->parameters.eccDetail.symmetric,
            &in->parameters.eccDetail.symmetric);
        out->parameters.eccDetail.scheme.scheme =
            in->parameters.eccDetail.scheme.scheme;
        if (out->parameters.eccDetail.scheme.scheme != TPM_ALG_NULL) {
            out->parameters.eccDetail.scheme.details.any.hashAlg =
                in->parameters.eccDetail.scheme.details.any.hashAlg;
        }
        out->parameters.eccDetail.curveID =
            in->parameters.eccDetail.curveID;
        out->parameters.eccDetail.kdf.scheme =
            in->parameters.eccDetail.kdf.scheme;
        if (out->parameters.eccDetail.kdf.scheme != TPM_ALG_NULL) {
            out->parameters.eccDetail.kdf.details.any.hashAlg =
                in->parameters.eccDetail.kdf.details.any.hashAlg;
        }
        ATHW_CopyEccParam(&out->unique.ecc.x,
            &in->unique.ecc.x);
        ATHW_CopyEccParam(&out->unique.ecc.y,
            &in->unique.ecc.y);
        break;
    default:
        ATHW_CopySymmetric(&out->parameters.asymDetail.symmetric,
            &in->parameters.asymDetail.symmetric);
        out->parameters.asymDetail.scheme.scheme =
            in->parameters.asymDetail.scheme.scheme;
        if (out->parameters.asymDetail.scheme.scheme != TPM_ALG_NULL)
            out->parameters.asymDetail.scheme.details.anySig.hashAlg =
                in->parameters.asymDetail.scheme.details.anySig.hashAlg;
        break;
    }
}

static void ATHW_CopyPub(TPM2B_PUBLIC* out, const TPM2B_PUBLIC* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        ATHW_CopyPubT(&out->publicArea, &in->publicArea);
    }
}

static void ATHW_CopyPriv(TPM2B_PRIVATE* out, const TPM2B_PRIVATE* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        if (out->size > (UINT16)sizeof(out->buffer))
            out->size = (UINT16)sizeof(out->buffer);
        XMEMCPY(out->buffer, in->buffer, out->size);
    }
}

void ATHW_CopyEccParam(TPM2B_ECC_PARAMETER* out,
    const TPM2B_ECC_PARAMETER* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        if (out->size > (UINT16)sizeof(out->buffer))
            out->size = (UINT16)sizeof(out->buffer);
        XMEMCPY(out->buffer, in->buffer, out->size);
    }
}

static void ATHW_CopyKeyFromBlob(ATHW_KEY* key, const ATHW_KEYBLOB* keyBlob)
{
    if (key != NULL && keyBlob != NULL) {
        key->handle.hndl = keyBlob->handle.hndl;
        ATHW_CopyAuth(&key->handle.auth, &keyBlob->handle.auth);
        ATHW_CopyName(&key->handle.name, &keyBlob->handle.name);
        ATHW_CopySymmetric(&key->handle.symmetric, &keyBlob->handle.symmetric);
        ATHW_CopyPub(&key->pub, &keyBlob->pub);
    }
}

static void ATHW_CopyNvPublic(TPMS_NV_PUBLIC* out, const TPMS_NV_PUBLIC* in)
{
    if (out != NULL && in != NULL) {
        out->attributes = in->attributes;
        out->authPolicy.size = in->authPolicy.size;
        if (out->authPolicy.size > 0) {
            if (out->authPolicy.size > (UINT16)sizeof(out->authPolicy.buffer)) {
                out->authPolicy.size = (UINT16)sizeof(out->authPolicy.buffer);
            }
            XMEMCPY(out->authPolicy.buffer, in->authPolicy.buffer, out->authPolicy.size);
        }
        out->dataSize = in->dataSize;
        out->nameAlg = in->nameAlg;
        out->nvIndex = in->nvIndex;
    }
}


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
//      ATHW_CopyEccParam(&out->unique.ecc.x,
//          &in->unique.ecc.x);
//      ATHW_CopyEccParam(&out->unique.ecc.y,
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
    
    tr_log("TPM2: Caps 0x%08x, Did 0x%04x, Vid 0x%04x, Rid 0x%2x \r\r\r\n",
        h->caps,
        h->did_vid >> 16,
        h->did_vid & 0xFFFF,
        h->rid);
    
    memset(&startupin, 0, sizeof startupin);
    startupin.startupType = TPM_SU_CLEAR;
    rc = TPM2_Startup(&startupin);
    
    if( rc != TPM_RC_SUCCESS && rc != TPM_RC_INITIALIZE) {
        tr_log("TPM2_Startup failed %d: %s\r\r\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    
    tr_log("TPM2_Starup pass \r\r\n");
    
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
    ATHW_DEV *h = NULL;
    
    if( dev == NULL ) {
        return -ATHW_ENULLP;
    }
    
    h = (ATHW_DEV *)dev;
    
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
    ATHW_DEV *dev = NULL;
    
    dev = (ATHW_DEV *)_dev;
        
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
    
    ATHW_DEV  *dev = (ATHW_DEV *)_dev;
    
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
    
    ATHW_DEV *dev = (ATHW_DEV *)_dev;
    
    if( dev == NULL ) {
        return -ATHW_ENULLP;
    }
    
    memset(&test, 0, sizeof test);
    test.fullTest = YES;
    rc = TPM2_SelfTest(&test);
    
    if( rc != ATHW_EOK ) {
        tr_log("TPM2_SelfTest failed 0x%x: %s \r\r\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    
    tr_log("TPM2_SelfTest pass \r\r\n");
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
    tr_log("tpm2 creation key: pub %d, priv %d \r\r\r\n",
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
    memset(&inload, 0x0, sizeof inload);
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


//
//int ATHW_CreateAndLoadKey(ATHW_DEV* dev, ATHW_KEY* key,
//    ATHW_HANDLE* parent, TPMT_PUBLIC* publicTemplate,
//    const byte* auth, int authSz)
//{
//    int rc;
//    ATHW_KEYBLOB keyBlob;
//
//    if (dev == NULL || key == NULL)
//        return BAD_FUNC_ARG;
//
//    rc = ATHW_CreateKey(dev, &keyBlob, parent, publicTemplate, auth, authSz);
//    if (rc == TPM_RC_SUCCESS) {
//        rc = ATHW_LoadKey(dev, &keyBlob, parent);
//    }
//
//    /* return loaded key */
//    XMEMCPY(key, &keyBlob, sizeof(ATHW_KEY));
//
//    return rc;
//}
//

int athw_tpm_create_and_load_key(void *handle, const uint8_t *auth, int authsz)
{
    int rc;
    athwtpm2_keyblob_t keyblob;
    athwtpm2_keyhnd_t   *h = (athwtpm2_keyhnd_t *)handle;
    if( handle == NULL || h->key == NULL ) {
        tr_log("NULL Param");

        return -ATHW_ENULLP;
    }
    
   // tr_log();
    h->blob = &keyblob;
   // tr_log();

    athw_memzero_s(h->blob, sizeof *h->blob);
   // tr_log();

    rc = athw_tpm_createkey(handle, auth, authsz);
   // tr_log();

    
    if( rc != 0 ) {
       // tr_log();

        goto exit; 
    }
    
    rc =  athw_tpm_loadkey(handle);
   // tr_log();

    
exit:
   // tr_log();

    memcpy(h->key, &keyblob,sizeof(ATHW_KEY));
   // tr_log();

    return rc;
    

}

int ATHWTPM2_EncryptSecret(ATHW_DEV* dev, const ATHW_KEY* tpmKey,
    TPM2B_DATA *data, TPM2B_ENCRYPTED_SECRET *secret,
    const char* label)
{
    int rc = NOT_COMPILED_IN;

    /* if a tpmKey is not present then we are using an unsalted session */
    if (dev == NULL || tpmKey == NULL || data == NULL || secret == NULL) {
        return TPM_RC_SUCCESS;
    }

#ifdef ATHW_DEBUG_TPM
    tr_log("Encrypt secret: Alg %s, Label %s\r\r\n",
        TPM2_GetAlgName(tpmKey->pub.publicArea.type), label);
#endif

#ifndef ATHW_NO_WOLFCRYPT
    switch (tpmKey->pub.publicArea.type) {
    #if defined(HAVE_ECC) && !defined(WC_NO_RNG) && defined(WOLFSSL_PUBLIC_MP)
        case TPM_ALG_ECC:
            rc = ATHW_EncryptSecret_ECC(dev, tpmKey, data, secret, label);
            break;
    #endif
    #if !defined(NO_RSA) && !defined(WC_NO_RNG)
        case TPM_ALG_RSA:
            rc = ATHW_EncryptSecret_RSA(dev, tpmKey, data, secret, label);
            break;
    #endif
        default:
            rc = NOT_COMPILED_IN;
            break;
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    tr_log("Encrypt Secret %d: %d bytes\r\r\n", rc, data->size);
    TPM2_PrintBin(data->buffer, data->size);
#endif
#endif /* !ATHW_NO_WOLFCRYPT */

    (void)label;

    return rc;
}

int ATHW_TPM2_KDFa(
    TPM_ALG_ID   hashAlg,   /* IN: hash algorithm used in HMAC */
    TPM2B_DATA  *keyIn,     /* IN: key */
    const char  *label,     /* IN: a 0-byte terminated label used in KDF */
    TPM2B_NONCE *contextU,  /* IN: context U (newer) */
    TPM2B_NONCE *contextV,  /* IN: context V */
    BYTE        *key,       /* OUT: key buffer */
    UINT32       keySz      /* IN: size of generated key in bytes */
)
{
#if !defined(ATHW_NO_WOLFCRYPT) && !defined(NO_HMAC)
    int ret, hashType;
    Hmac hmac_ctx;
    word32 counter = 0;
    int hLen, copyLen, lLen = 0;
    byte uint32Buf[sizeof(UINT32)];
    UINT32 sizeInBits = keySz * 8, pos;
    BYTE* keyStream = key;
    byte hash[WC_MAX_DIGEST_SIZE];

    if (key == NULL)
        return BAD_FUNC_ARG;

    hashType = TPM2_GetHashType(hashAlg);
    if (hashType == WC_HASH_TYPE_NONE)
        return NOT_COMPILED_IN;

    hLen = TPM2_GetHashDigestSize(hashAlg);
    if ( (hLen <= 0) || (hLen > WC_MAX_DIGEST_SIZE))
        return NOT_COMPILED_IN;

    /* get label length if provided, including null termination */
    if (label != NULL) {
        lLen = (int)XSTRLEN(label) + 1;
    }

    ret = wc_HmacInit(&hmac_ctx, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;

    /* generate required bytes - blocks sized digest */
    for (pos = 0; pos < keySz; pos += hLen) {
        /* KDFa counter starts at 1 */
        counter++;
        copyLen = hLen;

        /* start HMAC */
        if (keyIn) {
            ret = wc_HmacSetKey(&hmac_ctx, hashType, keyIn->buffer, keyIn->size);
        }
        else {
            ret = wc_HmacSetKey(&hmac_ctx, hashType, NULL, 0);
        }
        if (ret != 0)
            goto exit;

        /* add counter - KDFa i2 */
        TPM2_Packet_U32ToByteArray(counter, uint32Buf);
        ret = wc_HmacUpdate(&hmac_ctx, uint32Buf, (word32)sizeof(uint32Buf));
        if (ret != 0)
            goto exit;

        /* add label - KDFa label */
        if (label != NULL) {
            ret = wc_HmacUpdate(&hmac_ctx, (byte*)label, lLen);
            if (ret != 0)
                goto exit;
        }

        /* add contextU */
        if (contextU != NULL && contextU->size > 0) {
            ret = wc_HmacUpdate(&hmac_ctx, contextU->buffer, contextU->size);
            if (ret != 0)
                goto exit;
        }

        /* add contextV */
        if (contextV != NULL && contextV->size > 0) {
            ret = wc_HmacUpdate(&hmac_ctx, contextV->buffer, contextV->size);
            if (ret != 0)
                goto exit;
        }

        /* add size in bits */
        TPM2_Packet_U32ToByteArray(sizeInBits, uint32Buf);
        ret = wc_HmacUpdate(&hmac_ctx, uint32Buf, (word32)sizeof(uint32Buf));
        if (ret != 0)
            goto exit;

        /* get result */
        ret = wc_HmacFinal(&hmac_ctx, hash);
        if (ret != 0)
            goto exit;

        if ((UINT32)hLen > keySz - pos) {
          copyLen = keySz - pos;
        }

        XMEMCPY(keyStream, hash, copyLen);
        keyStream += copyLen;
    }
    ret = keySz;

exit:
    wc_HmacFree(&hmac_ctx);

    /* return length rounded up to nearest 8 multiple */
    return ret;
#else
    (void)hashAlg;
    (void)keyIn;
    (void)label;
    (void)contextU;
    (void)contextV;
    (void)key;
    (void)keySz;

    return NOT_COMPILED_IN;
#endif
}


int ATHWTPM2_SetAuthSession(ATHW_DEV* dev, int index,
    ATHW_SESSION* tpmSession, TPMA_SESSION sessionAttributes)
{
    int rc;

    if (dev == NULL || index >= MAX_SESSION_NUM) {
        return BAD_FUNC_ARG;
    }

    if (tpmSession == NULL) {
        /* clearing auth session */
        XMEMSET(&dev->session[index], 0, sizeof(TPM2_AUTH_SESSION));
        return TPM_RC_SUCCESS;
    }

    rc = athw_tpm_set_auth(dev, index, tpmSession->handle.hndl,
        &tpmSession->handle.auth, sessionAttributes, NULL);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_AUTH_SESSION* session = &dev->session[index];

        /* save off session attributes */
        tpmSession->sessionAttributes = sessionAttributes;

        /* define the symmetric algorithm */
        session->authHash = tpmSession->authHash;
        XMEMCPY(&session->symmetric, &tpmSession->handle.symmetric,
            sizeof(TPMT_SYM_DEF));

        /* fresh nonce generated in TPM2_CommandProcess based on this size */
        session->nonceCaller.size = TPM2_GetHashDigestSize(TPM_ALG_SHA256);

        /* Capture TPM provided nonce */
        session->nonceTPM.size = tpmSession->nonceTPM.size;
        XMEMCPY(session->nonceTPM.buffer, tpmSession->nonceTPM.buffer,
            session->nonceTPM.size);

        /* Parameter Encryption session will have an hmac added later.
         * Reserve space, the same way it was done for nonceCaller above.
         */
        if (session->sessionHandle != TPM_RS_PW &&
            ((session->sessionAttributes & TPMA_SESSION_encrypt) ||
             (session->sessionAttributes & TPMA_SESSION_decrypt))) {
            session->auth.size = TPM2_GetHashDigestSize(session->authHash);
        }
    }
    return rc;
}



int ATHWTPM2_StartSession(ATHW_DEV* dev, ATHW_SESSION* session,
    ATHW_KEY* tpmKey, ATHW_HANDLE* bind, TPM_SE sesType,
    int encDecAlg)
{
    int rc;
    StartAuthSession_In  authSesIn;
    StartAuthSession_Out authSesOut;
    TPM2B_AUTH* bindAuth = NULL;
    TPM2B_DATA keyIn;
    TPMI_ALG_HASH authHash = TPM_ALG_SHA256;
    int hashDigestSz;

    if (dev == NULL || session == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(session, 0, sizeof(ATHW_SESSION));
    XMEMSET(&authSesIn, 0, sizeof(authSesIn));

    authSesIn.authHash = authHash;
    hashDigestSz = TPM2_GetHashDigestSize(authHash);
    if (hashDigestSz <= 0) {
        return NOT_COMPILED_IN;
    }

    /* set session auth for key */
    if (tpmKey) {
        TPMA_SESSION sessionAttributes = 0;
        if (encDecAlg == TPM_ALG_CFB || encDecAlg == TPM_ALG_XOR) {
            /* if parameter encryption is enabled and key bind set, enable
             * encrypt/decrypt by default */
            sessionAttributes |= (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt);
        }
        athw_tpm_set_auth(dev, 0, tpmKey->handle.hndl, &tpmKey->handle.auth,
            sessionAttributes, NULL);
        authSesIn.tpmKey = tpmKey->handle.hndl;
    }
    else {
        athw_tpm_set_auth_password(dev, 0, NULL);
        authSesIn.tpmKey = (TPMI_DH_OBJECT)TPM_RH_NULL;
    }
    /* setup bind key */
    authSesIn.bind = (TPMI_DH_ENTITY)TPM_RH_NULL;
    if (bind) {
        authSesIn.bind = bind->hndl;
        bindAuth = &bind->auth;
    }

    authSesIn.sessionType = sesType;
    if (encDecAlg == TPM_ALG_CFB) {
        authSesIn.symmetric.algorithm = TPM_ALG_AES;
        authSesIn.symmetric.keyBits.aes = 128;
        authSesIn.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else if (encDecAlg == TPM_ALG_XOR) {
        authSesIn.symmetric.algorithm = TPM_ALG_XOR;
        authSesIn.symmetric.keyBits.xorr = TPM_ALG_SHA256;
        authSesIn.symmetric.mode.sym = TPM_ALG_NULL;
    }
    else {
        authSesIn.symmetric.algorithm = TPM_ALG_NULL;
    }
    authSesIn.nonceCaller.size = hashDigestSz;
    rc = TPM2_GetNonce(authSesIn.nonceCaller.buffer,
                       authSesIn.nonceCaller.size);
    if (rc < 0) {
    #ifdef ATHW_DEBUG_TPM
        tr_log("TPM2_GetNonce failed %d: %s\r\r\n", rc, TPM2_GetRCString(rc));
    #endif
        return rc;
    }

    if (authSesIn.tpmKey != TPM_RH_NULL) {
        /* Generate random salt */
        session->salt.size = hashDigestSz;
        rc = TPM2_GetNonce(session->salt.buffer, session->salt.size);
        if (rc != 0) {
            return rc;
        }

        /* Encrypt salt using "SECRET" */
        rc = ATHWTPM2_EncryptSecret(dev, tpmKey, (TPM2B_DATA*)&session->salt,
            &authSesIn.encryptedSalt, "SECRET");
        if (rc != 0) {
        #ifdef ATHW_DEBUG_TPM
            tr_log("Building encrypted salt failed %d: %s!\r\r\n", rc,
                TPM2_GetRCString(rc));
        #endif
            return rc;
        }
    }

    rc = TPM2_StartAuthSession(&authSesIn, &authSesOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef ATHW_DEBUG_TPM
        tr_log("TPM2_StartAuthSession failed %d: %s\r\r\n", rc,
            TPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Calculate "key" and store into auth */
    /* key is bindAuthValue || salt */
    XMEMSET(&keyIn, 0, sizeof(keyIn));
    if (bindAuth && bindAuth->size > 0) {
        XMEMCPY(&keyIn.buffer[keyIn.size], bindAuth->buffer, bindAuth->size);
        keyIn.size += bindAuth->size;
    }
    if (session->salt.size > 0) {
        XMEMCPY(&keyIn.buffer[keyIn.size], session->salt.buffer,
            session->salt.size);
        keyIn.size += session->salt.size;
    }

    if (keyIn.size > 0) {
        session->handle.auth.size = hashDigestSz;
        rc = ATHW_TPM2_KDFa(authSesIn.authHash, &keyIn, "ATH",
            &authSesOut.nonceTPM, &authSesIn.nonceCaller,
            session->handle.auth.buffer, session->handle.auth.size);
        if (rc != hashDigestSz) {
        #ifdef ATHW_DEBUG_TPM
            tr_log("KDFa ATH Gen Error %d\r\r\n", rc);
        #endif
            return TPM_RC_FAILURE;
        }
        rc = TPM_RC_SUCCESS;
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    tr_log("Session Key %d\r\r\n", session->handle.auth.size);
    TPM2_PrintBin(session->handle.auth.buffer, session->handle.auth.size);
#endif

    /* return session */
    session->type = authSesIn.sessionType;
    session->authHash = authSesIn.authHash;
    session->handle.hndl = authSesOut.sessionHandle;
    athw_tpm_copy_symmetric(&session->handle.symmetric, &authSesIn.symmetric);
    if (bind) {
        athw_tpm_copyname(&session->handle.name, &bind->name);
    }
    session->nonceCaller.size = authSesIn.nonceCaller.size;
    if (session->nonceCaller.size > (UINT16)sizeof(session->nonceCaller.buffer))
        session->nonceCaller.size = (UINT16)sizeof(session->nonceCaller.buffer);
    XMEMCPY(session->nonceCaller.buffer, authSesIn.nonceCaller.buffer,
        authSesIn.nonceCaller.size);
    session->nonceTPM.size = authSesOut.nonceTPM.size;
    if (session->nonceTPM.size > (UINT16)sizeof(session->nonceTPM.buffer))
        session->nonceTPM.size = (UINT16)sizeof(session->nonceTPM.buffer);
    XMEMCPY(session->nonceTPM.buffer, authSesOut.nonceTPM.buffer,
        session->nonceTPM.size);

#ifdef ATHW_DEBUG_TPM
    tr_log("TPM2_StartAuthSession: handle 0x%x, algorithm %s\r\r\r\n",
        (word32)session->handle.hndl,
        TPM2_GetAlgName(authSesIn.symmetric.algorithm));
#endif

    return rc;
}

    

//int athw_tpm_start_session(void *dev, TPM_SE type, int cipheralg)
//{
//    int rc;
//    StartAuthSession_In insession;
//    StartAuthSession_Out outsession;
//
//    athwtpm2_sessionhndl_t *session = (athwtpm2_sessionhndl_t *)dev;
//
//    TPM2B_AUTH *bindauth = NULL;
//    TPM2B_DATA keyin;
//    TPMI_ALG_HASH hashauth  =   TPM_ALG_SHA256;
//    int sz_digest = 0L;
//
//
//    if (session == NULL || session->dev  == NULL || session->session) {
//        return -ATHW_ENULLP;
//    }
//
//    athw_memzero_s(session->session, sizeof *session->session);
//    athw_memzero_s(&insession, sizeof insession);
//
//    insession.authHash = hashauth;
//    sz_digest = TPM2_GetHashDigestSize(hashauth);
//    if (sz_digest <= 0) {
//        return -ATHW_EINVAL;
//    }
//
//
//    // set session auth for key
//    if (session->key) {
//        TPMA_SESSION attrsession = 0;
//
//        if (cipheralg == TPM_ALG_CFB || cipheralg == TPM_ALG_XOR) {
//            attrsession |=  (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt);
//        }
//
//        athw_tpm_set_auth(session->dev, session->key->handle.hndl,
//                          &session->key->handle.auth,
//                          attrsession, NULL);
//        insession.tpmKey = session->key->handle.hndl;
//    }
//    else {
//        athw_tpm_set_auth_password(session->dev, 0, NULL);
//        insession.tpmKey = (TPMI_DH_OBJECT)TPM_RH_NULL;
//    }
//
//    // bind-key setup
//    insession.bind = (TPMI_DH_ENTITY)TPM_RH_NULL;
//    if (session->bindhndl) {
//        insession.bind = session->bindhndl;
//        bindauth = &session->bindhndl->auth;
//    }
//
//    insession.sessionType = type;
//    if (cipheralg == TPM_ALG_CFB) {
//        insession.symmetric.algorithm = TPM_ALG_AES;
//        insession.symmetric.keyBits.aes = 128;
//        insession.symmetric.mode.aes = TPM_ALG_CFB;
//    }
//    else if (cipheralg == TPM_ALG_XOR) {
//        insession.symmetric.algorithm = TPM_ALG_XOR;
//        insession.symmetric.keyBits.xorr = TPM_ALG_SHA256;
//        insession.symmetric.mode.sym = TPM_ALG_NULL;
//    }
//    else {
//        insession.symmetric.algorithm = TPM_ALG_NULL;
//    }
//
//    insession.nonceCaller.size = sz_digest;
//
//    rc = TPM2_GetNonce(insession.nonceCaller.buffer, insession.nonceCaller.size);
//    if (rc < 0) {
//        tr_log("TPM2_GetNonde failed (0x%x) - %s", rc, TPM2_GetRCString(rc));
//        return rc;
//    }
//
//    if (insession.tpmKey != TPM_RH_NULL) {
//        session->session->salt.size = sz_digest;
//        rc = TPM2_GetNonce(session->session->salt.buffer, session->session->salt.size);
//        if (rc != 0) {
//            tr_log("TPM2_GetNonde failed (0x%x) - %s", rc, TPM2_GetRCString(rc));
//            return rc;
//        }
//
////      if (session->dev == NULL || session->key || &session->session->salt == NULL) {
////      }
//
//        // Encrypt salt
//    }
//
//    rc = TPM2_StartAuthSession(&insession, &outsession);
//    if (rc != 0) {
//        tr_log("TPM2_StartAuthSession failed (%d) - %s", rc, TPM2_GetRCString(rc));
//        return rc;
//    }
//
//    // calculate key
//    athw_memzero_s(&keyin, sizeof keyin);
//    if (bindauth && bindauth->size > 0) {
//        memcpy(&keyin.buffer[keyin.size], bindauth->buffer, bindauth->size);
//        keyin.size += bindauth->size;
//    }
//
//    if (session->session->salt.size > 0) {
//        memcpy(&keyin.buffer[keyin.size], session->session->salt.buffer,
//               session->session->salt.size);
//        keyin.size += session->session->salt.size;
//    }
//
//    if (keyin.size > 0) {
//        session->session->handle.auth.size = sz_digest;
//        //rc = TPM2_KDFa
//
//        rc = ATHW_EOK;
//    }
//
//#ifdef ATHW_DEBUG_TPM_VERBOSE
//    //tr_log("Session key %d \r\r\n", session->session->handle.auth.size);
//    _athw_print_bin("Session key",
//                    session->session->handle.auth.buffer,
//                    session->session->handle.auth.size);
//#endif
//
//    //return session
//    session->session->type =  insession.sessionType;
//    session->session->authHash = insession.authHash;
//    session->session->handle.hndl = outsession.sessionHandle;
//
//    athw_tpm_copy_symmetric(&session->session->handle.symmetric,
//                            &insession.symmetric);
//    if (bind) {
//        athw_tpm_copyname(&session->session->handle.name,
//                            &session->bindhndl->name);
//    }
//
//    session->session->nonceCaller.size = insession.nonceCaller.size;
//    if (session->session->nonceCaller.size >
//            (UINT16)sizeof(session->session->nonceCaller.buffer))
//        session->session->nonceCaller.size = (UINT16)sizeof(session->session->nonceCaller.buffer)
//
//    memcpy(session->session->nonceCaller.buffer,
//            insession.nonceCaller.buffer,
//            insession.nonceCaller.size);
//    session->session->nonceTPM.size = outsession.nonceTPM.size;
//
//    if (session->session->nonceTPM.size > (UINT16)sizeof(session->session->nonceTPM.buffer))
//        session->session->nonceTPM.size = (UINT16)sizeof(session->session->nonceTPM.buffer);
//
//    memcpy(session->session->nonceTPM.buffer,
//            outsession.nonceTPM.buffer,
//            session->session->nonceTPM.size);
//
//#ifdef ATHW_DEBUG_TPM
//    tr_log("TPM2_StartAuthSession: handle 0x%x, algorithm %s\r\r\n",
//        (uint32_t)session->session->handle.hndl,
//        TPM2_GetAlgName(insession.symmetric.algorithm));
//#endif
//
//    return rc;
//
//}

int ATHW_ReadPublicKey(ATHW_DEV* dev, ATHW_KEY* key,
    const TPM_HANDLE handle)
{
    int rc;
    ReadPublic_In  readPubIn;
    ReadPublic_Out readPubOut;

    if (dev == NULL || key == NULL)
        return BAD_FUNC_ARG;

    /* Read public key */
    XMEMSET(&readPubIn, 0, sizeof(readPubIn));
    readPubIn.objectHandle = handle;
    rc = TPM2_ReadPublic(&readPubIn, &readPubOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef ATHW_DEBUG_TPM
        tr_log("TPM2_ReadPublic failed %d: %s\r\r\n", rc, TPM2_GetRCString(rc));
    #endif
        return rc;
    }

    key->handle.hndl = readPubIn.objectHandle;
    athw_tpm_copy_symmetric(&key->handle.symmetric,
            &readPubOut.outPublic.publicArea.parameters.asymDetail.symmetric);
    athw_tpm_copyname(&key->handle.name, &readPubOut.name);
    athw_tpm_copy_pub(&key->pub, &readPubOut.outPublic);

#ifdef ATHW_DEBUG_TPM
    tr_log("TPM2_ReadPublic Handle 0x%x: pub %d, name %d, qualifiedName %d\r\r\n",
        (word32)readPubIn.objectHandle,
        readPubOut.outPublic.size, readPubOut.name.size,
        readPubOut.qualifiedName.size);
#endif

    return rc;
}

static int GetKeyTemplateRSA(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID nameAlg, TPMA_OBJECT objectAttributes, int keyBits, int exponent,
    TPM_ALG_ID sigScheme, TPM_ALG_ID sigHash)
{
    if (publicTemplate == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(publicTemplate, 0, sizeof(TPMT_PUBLIC));
    publicTemplate->type = TPM_ALG_RSA;
    publicTemplate->unique.rsa.size = keyBits / 8;
    publicTemplate->nameAlg = nameAlg;
    publicTemplate->objectAttributes = objectAttributes;
    publicTemplate->parameters.rsaDetail.keyBits = keyBits;
    publicTemplate->parameters.rsaDetail.exponent = exponent;
    publicTemplate->parameters.rsaDetail.scheme.scheme = sigScheme;
    publicTemplate->parameters.rsaDetail.scheme.details.anySig.hashAlg = sigHash;
    /* For fixedParent or (decrypt and restricted) enable symmetric */
    if ((objectAttributes & TPMA_OBJECT_fixedParent) ||
           ((objectAttributes & TPMA_OBJECT_decrypt) &&
            (objectAttributes & TPMA_OBJECT_restricted))) {
        publicTemplate->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
        publicTemplate->parameters.rsaDetail.symmetric.keyBits.aes = 128;
        publicTemplate->parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else {
        publicTemplate->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    }

    return TPM_RC_SUCCESS;
}

static int GetKeyTemplateECC(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID nameAlg, TPMA_OBJECT objectAttributes, TPM_ECC_CURVE curve,
    TPM_ALG_ID sigScheme, TPM_ALG_ID sigHash)
{
    int curveSz = TPM2_GetCurveSize(curve);

    if (publicTemplate == NULL || curveSz == 0)
        return BAD_FUNC_ARG;

#if defined(NO_ECC256) && defined(HAVE_ECC384) && ECC_MIN_KEY_SZ <= 384
    /* make sure we use a curve that is enabled */
    if (curve == TPM_ECC_NIST_P256) {
        curve = TPM_ECC_NIST_P384;
        nameAlg = TPM_ALG_SHA384;
        sigHash = TPM_ALG_SHA384;
    }
#endif

    XMEMSET(publicTemplate, 0, sizeof(TPMT_PUBLIC));
    publicTemplate->type = TPM_ALG_ECC;
    publicTemplate->nameAlg = nameAlg;
    publicTemplate->unique.ecc.x.size = curveSz;
    publicTemplate->unique.ecc.y.size = curveSz;
    publicTemplate->objectAttributes = objectAttributes;
    /* For fixedParent or (decrypt and restricted) enable symmetric */
    if ((objectAttributes & TPMA_OBJECT_fixedParent) ||
           ((objectAttributes & TPMA_OBJECT_decrypt) &&
            (objectAttributes & TPMA_OBJECT_restricted))) {
        publicTemplate->parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
        publicTemplate->parameters.eccDetail.symmetric.keyBits.aes = 128;
        publicTemplate->parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else {
        publicTemplate->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    }
    /* TPM_ALG_ECDSA or TPM_ALG_ECDH */
    publicTemplate->parameters.eccDetail.scheme.scheme = sigScheme;
    publicTemplate->parameters.eccDetail.scheme.details.ecdsa.hashAlg = sigHash;
    publicTemplate->parameters.eccDetail.curveID = curve;
    publicTemplate->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;

    return TPM_RC_SUCCESS;
}



int ATHW_CreateSRK(ATHW_DEV* dev, ATHW_KEY* srkKey, TPM_ALG_ID alg,
    const byte* auth, int authSz)
{
    int rc;
    TPMT_PUBLIC publicTemplate;

    /* Supported algorithms for SRK are only 2048bit RSA & ECC */
    if (alg == TPM_ALG_RSA) {
        rc = ATHW_GetKeyTemplate_RSA_SRK(&publicTemplate);
    }
    else if (alg == TPM_ALG_ECC) {
        rc = ATHW_GetKeyTemplate_ECC_SRK(&publicTemplate);
    }
    else {
        /* Supported algorithms for SRK are only RSA 2048-bit & ECC P256 */
        return BAD_FUNC_ARG;
    }
    /* GetKeyTemplate check */
    if (rc != 0)
        return rc;

    rc = ATHW_CreatePrimaryKey(dev, srkKey, TPM_RH_OWNER,
        &publicTemplate, auth, authSz);

    return rc;
}

int ATHW_GetKeyTemplate_RSA_SRK(TPMT_PUBLIC* publicTemplate)
{
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);

    return GetKeyTemplateRSA(publicTemplate, TPM_ALG_SHA256,
        objectAttributes, 2048, 0, TPM_ALG_NULL, TPM_ALG_NULL);
}

int ATHW_GetKeyTemplate_ECC_SRK(TPMT_PUBLIC* publicTemplate)
{
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);

    return GetKeyTemplateECC(publicTemplate, TPM_ALG_SHA256,
        objectAttributes, TPM_ECC_NIST_P256, TPM_ALG_NULL, TPM_ALG_NULL);
}

int ATHW_CreatePrimaryKey(ATHW_DEV* dev, ATHW_KEY* key,
    TPM_HANDLE primaryHandle, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz)
{
    int rc;
    CreatePrimary_In  createPriIn;
    CreatePrimary_Out createPriOut;

    if (dev == NULL || key == NULL || publicTemplate == NULL)
        return BAD_FUNC_ARG;

    /* set session auth to blank */
    athw_tpm_set_auth_password(dev, 0, NULL);

    /* clear output key buffer */
    XMEMSET(key, 0, sizeof(ATHW_KEY));

    /* setup create primary command */
    XMEMSET(&createPriIn, 0, sizeof(createPriIn));
    /* TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM or TPM_RH_NULL */
    createPriIn.primaryHandle = primaryHandle;
    if (auth && authSz > 0) {
        int nameAlgDigestSz = TPM2_GetHashDigestSize(publicTemplate->nameAlg);
        /* truncate if longer than name size */
        if (nameAlgDigestSz > 0 && authSz > nameAlgDigestSz)
            authSz = nameAlgDigestSz;
        XMEMCPY(createPriIn.inSensitive.sensitive.userAuth.buffer, auth, authSz);
        /* make sure auth is same size as nameAlg digest size */
        if (nameAlgDigestSz > 0 && authSz < nameAlgDigestSz)
            authSz = nameAlgDigestSz;
        createPriIn.inSensitive.sensitive.userAuth.size = authSz;
    }
    XMEMCPY(&createPriIn.inPublic.publicArea, publicTemplate,
        sizeof(TPMT_PUBLIC));
    rc = TPM2_CreatePrimary(&createPriIn, &createPriOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef ATHW_DEBUG_TPM
        tr_log("TPM2_CreatePrimary: failed %d: %s\r\r\n", rc,
            TPM2_GetRCString(rc));
    #endif
        return rc;
    }
    key->handle.hndl = createPriOut.objectHandle;
    athw_tpm_copyauth(&key->handle.auth,
        &createPriIn.inSensitive.sensitive.userAuth);
    athw_tpm_copyname(&key->handle.name, &createPriOut.name);
    athw_tpm_copy_symmetric(&key->handle.symmetric,
        &createPriOut.outPublic.publicArea.parameters.asymDetail.symmetric);
    athw_tpm_copy_pub(&key->pub, &createPriOut.outPublic);

#ifdef ATHW_DEBUG_TPM
    tr_log("TPM2_CreatePrimary: 0x%x (%d bytes)\r\r\n",
        (word32)key->handle.hndl, key->pub.size);
#endif

    return rc;
}

int ATHW_UnloadHandle(ATHW_DEV* dev, ATHW_HANDLE* handle)
{
    int rc;
    FlushContext_In in;

    if (dev == NULL || handle == NULL)
        return BAD_FUNC_ARG;

    /* don't try and unload null or persistent handles */
    if (handle->hndl == 0 || handle->hndl == TPM_RH_NULL ||
        (handle->hndl >= PERSISTENT_FIRST && handle->hndl <= PERSISTENT_LAST)) {
        return TPM_RC_SUCCESS;
    }

    XMEMSET(&in, 0, sizeof(in));
    in.flushHandle = handle->hndl;
    rc = TPM2_FlushContext(&in);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef ATHW_DEBUG_TPM
        tr_log("TPM2_FlushContext failed %d: %s\r\r\n", rc,
            TPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef ATHW_DEBUG_TPM
    tr_log("TPM2_FlushContext: Closed handle 0x%x\r\r\n", (word32)handle->hndl);
#endif

    handle->hndl = TPM_RH_NULL;

    return TPM_RC_SUCCESS;
}

/* primaryHandle must be owner or platform hierarchy */
/* Owner    Persistent Handle Range: 0x81000000 to 0x817FFFFF */
/* Platform Persistent Handle Range: 0x81800000 to 0x81FFFFFF */
int ATHW_NVStoreKey(ATHW_DEV* dev, TPM_HANDLE primaryHandle,
    ATHW_KEY* key, TPM_HANDLE persistentHandle)
{
    int rc;
    EvictControl_In in;

    if (dev == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }
    if (primaryHandle == TPM_RH_OWNER &&
        (persistentHandle < PERSISTENT_FIRST ||
         persistentHandle > PERSISTENT_LAST)) {
        return BAD_FUNC_ARG;
    }
    if (primaryHandle == TPM_RH_PLATFORM &&
        (persistentHandle < PLATFORM_PERSISTENT ||
         persistentHandle > PERSISTENT_LAST)) {
        return BAD_FUNC_ARG;
    }

    /* if key is already persistent then just return success */
    if (key->handle.hndl == persistentHandle)
        return TPM_RC_SUCCESS;

    /* set session auth to blank */
    athw_tpm_set_auth_password(dev, 0, NULL);

    /* Move key into NV to persist */
    XMEMSET(&in, 0, sizeof(in));
    in.auth = primaryHandle;
    in.objectHandle = key->handle.hndl;
    in.persistentHandle = persistentHandle;

    rc = TPM2_EvictControl(&in);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef WOLFTPM_WINAPI
        if (rc == (int)TPM_E_COMMAND_BLOCKED) { /* 0x80280400 */
        #ifdef ATHW_DEBUG_TPM
            tr_log("TPM2_EvictControl (storing key to NV) not allowed on "
                   "Windows TBS (err 0x%x)\r\n", rc);
        #endif
            rc = TPM_RC_NV_UNAVAILABLE;
        }
    #endif

    #ifdef ATHW_DEBUG_TPM
        tr_log("TPM2_EvictControl failed %d: %s\r\n", rc,
            TPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef ATHW_DEBUG_TPM
    tr_log("TPM2_EvictControl Auth 0x%x, Key 0x%x, Persistent 0x%x\r\n",
        (word32)in.auth, (word32)in.objectHandle, (word32)in.persistentHandle);
#endif

    /* unload transient handle */
    ATHW_UnloadHandle(dev, &key->handle);

    /* replace handle with persistent one */
    key->handle.hndl = persistentHandle;

    return rc;
}

int ATHW_UnsetAuth(ATHW_DEV* dev, int index)
{
    TPM2_AUTH_SESSION* session;

    if (dev == NULL || index >= MAX_SESSION_NUM || index < 0) {
        return BAD_FUNC_ARG;
    }

    session = &dev->session[index];
    XMEMSET(session, 0, sizeof(TPM2_AUTH_SESSION));

    return TPM2_SetSessionAuth(dev->session);
}

int ATHW_UnsetAuthSession(ATHW_DEV* dev, int index,
    ATHW_SESSION* tpmSession)
{
    TPM2_AUTH_SESSION* devSession;

    if (dev == NULL || tpmSession == NULL ||
            index >= MAX_SESSION_NUM || index < 0) {
        return BAD_FUNC_ARG;
    }

    devSession = &dev->session[index];

    /* save off nonce from TPM to support continued use of session */
    XMEMCPY(&tpmSession->nonceTPM, &devSession->nonceTPM, sizeof(TPM2B_NONCE));

    XMEMSET(devSession, 0, sizeof(TPM2_AUTH_SESSION));

    return TPM2_SetSessionAuth(dev->session);
}

int ATHW_SetAuth(ATHW_DEV* dev, int index,
    TPM_HANDLE sessionHandle, const TPM2B_AUTH* auth,
    TPMA_SESSION sessionAttributes, const TPM2B_NAME* name)
{
    TPM2_AUTH_SESSION* session;

    if (dev == NULL || index >= MAX_SESSION_NUM || index < 0) {
        return BAD_FUNC_ARG;
    }

    session = &dev->session[index];
    XMEMSET(session, 0, sizeof(TPM2_AUTH_SESSION));
    session->sessionHandle = sessionHandle;
    session->sessionAttributes = sessionAttributes;
    if (auth) {
        session->auth.size = auth->size;
        XMEMCPY(session->auth.buffer, auth->buffer, auth->size);
    }
    if (name) {
        session->name.size = name->size;
        XMEMCPY(session->name.name, name->name, name->size);
    }

    TPM2_SetSessionAuth(dev->session);

    return TPM_RC_SUCCESS;
}

int ATHW_SetAuthPassword(ATHW_DEV* dev, int index,
    const TPM2B_AUTH* auth)
{
    return ATHW_SetAuth(dev, index, TPM_RS_PW, auth, 0, NULL);
}

int ATHW_SetAuthHandle(ATHW_DEV* dev, int index,
    const ATHW_HANDLE* handle)
{
    const TPM2B_AUTH* auth = NULL;
    const TPM2B_NAME* name = NULL;
    /* don't set auth for policy session */
    if (dev->ctx.session == NULL || handle->policyAuth) {
        return 0;
    }
    if (handle) {
        auth = &handle->auth;
        name = &handle->name;
    }
    return ATHW_SetAuth(dev, index, TPM_RS_PW, auth, 0, name);
}

int ATHW_SetAuthHandleName(ATHW_DEV* dev, int index,
    const ATHW_HANDLE* handle)
{
    const TPM2B_NAME* name = NULL;
    TPM2_AUTH_SESSION* session;

    if (dev == NULL || handle == NULL || index >= MAX_SESSION_NUM) {
        return BAD_FUNC_ARG;
    }

    name = &handle->name;
    session = &dev->session[index];

    if (session->auth.size == 0 && handle->auth.size > 0) {
        session->auth.size = handle->auth.size;
        XMEMCPY(session->auth.buffer, handle->auth.buffer, handle->auth.size);
    }
    session->name.size = name->size;
    XMEMCPY(session->name.name, name->name, session->name.size);

    return TPM_RC_SUCCESS;
}

int ATHW_SetAuthSession(ATHW_DEV* dev, int index,
    ATHW_SESSION* tpmSession, TPMA_SESSION sessionAttributes)
{
    int rc;

    if (dev == NULL || index >= MAX_SESSION_NUM) {
        return BAD_FUNC_ARG;
    }

    if (tpmSession == NULL) {
        /* clearing auth session */
        XMEMSET(&dev->session[index], 0, sizeof(TPM2_AUTH_SESSION));
        return TPM_RC_SUCCESS;
    }

    rc = ATHW_SetAuth(dev, index, tpmSession->handle.hndl,
        &tpmSession->handle.auth, sessionAttributes, NULL);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_AUTH_SESSION* session = &dev->session[index];

        /* save off session attributes */
        tpmSession->sessionAttributes = sessionAttributes;

        /* define the symmetric algorithm */
        session->authHash = tpmSession->authHash;
        XMEMCPY(&session->symmetric, &tpmSession->handle.symmetric,
            sizeof(TPMT_SYM_DEF));

        /* fresh nonce generated in TPM2_CommandProcess based on this size */
        session->nonceCaller.size = TPM2_GetHashDigestSize(TPM_ALG_SHA256);

        /* Capture TPM provided nonce */
        session->nonceTPM.size = tpmSession->nonceTPM.size;
        XMEMCPY(session->nonceTPM.buffer, tpmSession->nonceTPM.buffer,
            session->nonceTPM.size);

        /* Parameter Encryption session will have an hmac added later.
         * Reserve space, the same way it was done for nonceCaller above.
         */
        if (session->sessionHandle != TPM_RS_PW &&
            ((session->sessionAttributes & TPMA_SESSION_encrypt) ||
             (session->sessionAttributes & TPMA_SESSION_decrypt))) {
            session->auth.size = TPM2_GetHashDigestSize(session->authHash);
        }
    }
    return rc;
}


int ATHW_HashStart(ATHW_DEV* dev, ATHW_HASH* hash,
    TPMI_ALG_HASH hashAlg, const byte* usageAuth, word32 usageAuthSz)
{
    int rc;
    HashSequenceStart_In in;
    HashSequenceStart_Out out;

    if (dev == NULL || hash == NULL || hashAlg == TPM_ALG_NULL ||
        (usageAuthSz > 0 && usageAuth == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* Capture usage auth */
    if (usageAuthSz > sizeof(hash->handle.auth.buffer))
        usageAuthSz = sizeof(hash->handle.auth.buffer);
    XMEMSET(hash, 0, sizeof(ATHW_HASH));
    hash->handle.auth.size = usageAuthSz;
    if (usageAuth != NULL)
        XMEMCPY(hash->handle.auth.buffer, usageAuth, usageAuthSz);

    XMEMSET(&in, 0, sizeof(in));
    ATHW_CopyAuth(&in.auth, &hash->handle.auth);
    in.hashAlg = hashAlg;
    rc = TPM2_HashSequenceStart(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef ATHW_TPM_DEBUG
        tr_log("TPM2_HashSequenceStart failed 0x%x: %s\r\n", rc,
            TPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Capture hash sequence handle */
    hash->handle.hndl = out.sequenceHandle;

#ifdef ATHW_TPM_DEBUG
    tr_log("ATHW_HashStart: Handle 0x%x\r\n",
        (word32)out.sequenceHandle);
#endif

    return rc;
}

int ATHW_HashUpdate(ATHW_DEV* dev, ATHW_HASH* hash,
    const byte* data, word32 dataSz)
{
    int rc = TPM_RC_SUCCESS;
    SequenceUpdate_In in;
    word32 pos = 0, hashSz;

    if (dev == NULL || hash == NULL || (data == NULL && dataSz > 0) ||
            hash->handle.hndl == 0) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for hash handle */
    ATHW_SetAuthHandle(dev, 0, &hash->handle);

    XMEMSET(&in, 0, sizeof(in));
    in.sequenceHandle = hash->handle.hndl;

    while (pos < dataSz) {
        hashSz = dataSz - pos;
        if (hashSz > sizeof(in.buffer.buffer))
            hashSz = sizeof(in.buffer.buffer);

        in.buffer.size = hashSz;
        XMEMCPY(in.buffer.buffer, &data[pos], hashSz);
        rc = TPM2_SequenceUpdate(&in);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef ATHW_TPM_DEBUG
            tr_log("TPM2_SequenceUpdate failed 0x%x: %s\r\n", rc,
                TPM2_GetRCString(rc));
        #endif
            return rc;
        }
        pos += hashSz;
    }

#ifdef ATHW_TPM_DEBUG
    tr_log("ATHW_HashUpdate: Handle 0x%x, DataSz %d\r\n",
        (word32)in.sequenceHandle, dataSz);
#endif

    return rc;
}

int ATHW_HashFinish(ATHW_DEV* dev, ATHW_HASH* hash,
    byte* digest, word32* digestSz)
{
    int rc;
    SequenceComplete_In in;
    SequenceComplete_Out out;

    if (dev == NULL || hash == NULL || digest == NULL || digestSz == NULL ||
            hash->handle.hndl == 0) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for hash handle */
    ATHW_SetAuthHandle(dev, 0, &hash->handle);

    XMEMSET(&in, 0, sizeof(in));
    in.sequenceHandle = hash->handle.hndl;
    in.hierarchy = TPM_RH_NULL;
    rc = TPM2_SequenceComplete(&in, &out);

    /* mark hash handle as done */
    hash->handle.hndl = TPM_RH_NULL;

    if (rc != TPM_RC_SUCCESS) {
    #ifdef ATHW_TPM_DEBUG
        tr_log("TPM2_SequenceComplete failed 0x%x: %s: Handle 0x%x\r\n", rc,
            TPM2_GetRCString(rc), (word32)in.sequenceHandle);
    #endif
        return rc;
    }

    if (out.result.size > *digestSz)
        out.result.size = *digestSz;
    *digestSz = out.result.size;
    XMEMCPY(digest, out.result.buffer, *digestSz);

#ifdef ATHW_TPM_DEBUG
    tr_log("ATHW_HashFinish: Handle 0x%x, DigestSz %d\r\n",
        (word32)in.sequenceHandle, *digestSz);
#endif

    return rc;
}




//
//int ATHWTPM2_StartSession(ATHW_DEV* dev, ATHW_SESSION* session,
//    ATHW_KEY* tpmKey, ATHW_HANDLE* bind, TPM_SE sesType,
//    int encDecAlg)
//{
//    int rc;
//    StartAuthSession_In  authSesIn;
//    StartAuthSession_Out authSesOut;
//    TPM2B_AUTH* bindAuth = NULL;
//    TPM2B_DATA keyIn;
//    TPMI_ALG_HASH authHash = TPM_ALG_SHA256;
//    int hashDigestSz;
//
//    if (dev == NULL || session == NULL)
//        return BAD_FUNC_ARG;
//
//    XMEMSET(session, 0, sizeof(ATHW_SESSION));
//    XMEMSET(&authSesIn, 0, sizeof(authSesIn));
//
//    authSesIn.authHash = authHash;
//    hashDigestSz = TPM2_GetHashDigestSize(authHash);
//    if (hashDigestSz <= 0) {
//        return NOT_COMPILED_IN;
//    }
//
//    /* set session auth for key */
//    if (tpmKey) {
//        TPMA_SESSION sessionAttributes = 0;
//        if (encDecAlg == TPM_ALG_CFB || encDecAlg == TPM_ALG_XOR) {
//            /* if parameter encryption is enabled and key bind set, enable
//             * encrypt/decrypt by default */
//            sessionAttributes |= (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt);
//        }
//        ATHW_SetAuth(dev, 0, tpmKey->handle.hndl, &tpmKey->handle.auth,
//            sessionAttributes, NULL);
//        authSesIn.tpmKey = tpmKey->handle.hndl;
//    }
//    else {
//        ATHW_SetAuthPassword(dev, 0, NULL);
//        authSesIn.tpmKey = (TPMI_DH_OBJECT)TPM_RH_NULL;
//    }
//    /* setup bind key */
//    authSesIn.bind = (TPMI_DH_ENTITY)TPM_RH_NULL;
//    if (bind) {
//        authSesIn.bind = bind->hndl;
//        bindAuth = &bind->auth;
//    }
//
//    authSesIn.sessionType = sesType;
//    if (encDecAlg == TPM_ALG_CFB) {
//        authSesIn.symmetric.algorithm = TPM_ALG_AES;
//        authSesIn.symmetric.keyBits.aes = 128;
//        authSesIn.symmetric.mode.aes = TPM_ALG_CFB;
//    }
//    else if (encDecAlg == TPM_ALG_XOR) {
//        authSesIn.symmetric.algorithm = TPM_ALG_XOR;
//        authSesIn.symmetric.keyBits.xorr = TPM_ALG_SHA256;
//        authSesIn.symmetric.mode.sym = TPM_ALG_NULL;
//    }
//    else {
//        authSesIn.symmetric.algorithm = TPM_ALG_NULL;
//    }
//    authSesIn.nonceCaller.size = hashDigestSz;
//    rc = TPM2_GetNonce(authSesIn.nonceCaller.buffer,
//                       authSesIn.nonceCaller.size);
//    if (rc < 0) {
//    #ifdef ATHW_DEBUG_TPM
//        tr_log("TPM2_GetNonce failed %d: %s\r\r\n", rc, TPM2_GetRCString(rc));
//    #endif
//        return rc;
//    }
//
//    if (authSesIn.tpmKey != TPM_RH_NULL) {
//        /* Generate random salt */
//        session->salt.size = hashDigestSz;
//        rc = TPM2_GetNonce(session->salt.buffer, session->salt.size);
//        if (rc != 0) {
//            return rc;
//        }
//
//        /* Encrypt salt using "SECRET" */
//        rc = ATHW_EncryptSecret(dev, tpmKey, (TPM2B_DATA*)&session->salt,
//            &authSesIn.encryptedSalt, "SECRET");
//        if (rc != 0) {
//        #ifdef ATHW_DEBUG_TPM
//            tr_log("Building encrypted salt failed %d: %s!\r\r\n", rc,
//                TPM2_GetRCString(rc));
//        #endif
//            return rc;
//        }
//    }
//
//    rc = TPM2_StartAuthSession(&authSesIn, &authSesOut);
//    if (rc != TPM_RC_SUCCESS) {
//    #ifdef ATHW_DEBUG_TPM
//        tr_log("TPM2_StartAuthSession failed %d: %s\r\r\n", rc,
//            TPM2_GetRCString(rc));
//    #endif
//        return rc;
//    }
//
//    /* Calculate "key" and store into auth */
//    /* key is bindAuthValue || salt */
//    XMEMSET(&keyIn, 0, sizeof(keyIn));
//    if (bindAuth && bindAuth->size > 0) {
//        XMEMCPY(&keyIn.buffer[keyIn.size], bindAuth->buffer, bindAuth->size);
//        keyIn.size += bindAuth->size;
//    }
//    if (session->salt.size > 0) {
//        XMEMCPY(&keyIn.buffer[keyIn.size], session->salt.buffer,
//            session->salt.size);
//        keyIn.size += session->salt.size;
//    }
//
//    if (keyIn.size > 0) {
//        session->handle.auth.size = hashDigestSz;
//        rc = TPM2_KDFa(authSesIn.authHash, &keyIn, "ATH",
//            &authSesOut.nonceTPM, &authSesIn.nonceCaller,
//            session->handle.auth.buffer, session->handle.auth.size);
//        if (rc != hashDigestSz) {
//        #ifdef ATHW_DEBUG_TPM
//            tr_log("KDFa ATH Gen Error %d\r\r\n", rc);
//        #endif
//            return TPM_RC_FAILURE;
//        }
//        rc = TPM_RC_SUCCESS;
//    }
//
//#ifdef ATHW_DEBUG_TPM
//    tr_log("Session Key %d\r\r\n", session->handle.auth.size);
//    TPM2_PrintBin(session->handle.auth.buffer, session->handle.auth.size);
//#endif
//
//    /* return session */
//    session->type = authSesIn.sessionType;
//    session->authHash = authSesIn.authHash;
//    session->handle.hndl = authSesOut.sessionHandle;
//    athw_tpm_copy_symmetric(&session->handle.symmetric, &authSesIn.symmetric);
//    if (bind) {
//        athw_tpm_copyname(&session->handle.name, &bind->name);
//    }
//    session->nonceCaller.size = authSesIn.nonceCaller.size;
//    if (session->nonceCaller.size > (UINT16)sizeof(session->nonceCaller.buffer))
//        session->nonceCaller.size = (UINT16)sizeof(session->nonceCaller.buffer);
//    XMEMCPY(session->nonceCaller.buffer, authSesIn.nonceCaller.buffer,
//        authSesIn.nonceCaller.size);
//    session->nonceTPM.size = authSesOut.nonceTPM.size;
//    if (session->nonceTPM.size > (UINT16)sizeof(session->nonceTPM.buffer))
//        session->nonceTPM.size = (UINT16)sizeof(session->nonceTPM.buffer);
//    XMEMCPY(session->nonceTPM.buffer, authSesOut.nonceTPM.buffer,
//        session->nonceTPM.size);
//
//#ifdef ATHW_DEBUG_TPM
//    tr_log("TPM2_StartAuthSession: handle 0x%x, algorithm %s\r\r\n",
//        (word32)session->handle.hndl,
//        TPM2_GetAlgName(authSesIn.symmetric.algorithm));
//#endif
//
//    return rc;
//}
//









