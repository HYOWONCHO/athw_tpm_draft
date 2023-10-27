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
    
    if( dev == NULL || buf == NULL) {
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

int athw_tpm_set_auth_handle(void *_dev, int index, const WOLFTPM2_HANDLE *handle)
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

int athw_tpm_enc_dec_block(void *dev, WOLFTPM2_KEY *key, 
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


int athw_tpm_encrypt_decrypt(void *dev, WOLFTPM2_KEY *key, const uint8_t *in,
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

