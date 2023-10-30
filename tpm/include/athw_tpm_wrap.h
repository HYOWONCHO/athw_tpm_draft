#ifndef _ATHW_TPM_WRAP_H
#define _ATHW_TPM_WRAP_H

#ifdef _cplusplus
extern "C" {
#endif

#include "tpm2_wrap.h"

typedef WOLFTPM2_DEV        athwtpm2_dev_t;
typedef WOLFTPM2_KEYBLOB    athwtpm2_keyblob_t;
typedef WOLFTPM2_HANDLE     athwtpm2_handle_t;
typedef WOLFTPM2_KEY        athwtpm2_key_t;
typedef WOLFTPM2_BUFFER     athwtpm2_buf_t;
typedef WOLFTPM2_SESSION    athwtpm2_session_t;



typedef WOLFTPM2_DEV        ATHW_DEV;
typedef WOLFTPM2_KEYBLOB    ATHW_KEYBLOB;
typedef WOLFTPM2_HANDLE     ATHW_HANDLE;
typedef WOLFTPM2_KEY        ATHW_KEY;
typedef WOLFTPM2_BUFFER     ATHW_BUFFER;
typedef WOLFTPM2_SESSION    ATHW_SESSION;



typedef struct _athwtpm2_keyhnd_t {
    athwtpm2_dev_t          *dev;
    athwtpm2_keyblob_t      *blob;
    athwtpm2_handle_t       *parent;
    athwtpm2_key_t          *key;
    TPMT_PUBLIC             *pub; // need to change the name from pub to pubalgo
}athwtpm2_keyhnd_t;

typedef struct _athwtpm2_sessionhndl_t {
    athwtpm2_dev_t          *dev;
    athwtpm2_session_t      *session;
    athwtpm2_key_t          *key;
    athwtpm2_handle_t       *bindhndl;
}athwtpm2_sessionhndl_t;



/*!
 * \fn  int athw_tpm_init(void *dev, void *iocb, void *userctx) 
 * \brief initialization of TPM 
 * 
 * \author rocke (2023-10-26)
 * 
 * \param dev           Device handle buffer     
 * \param iocb          I/O Callback
 * \param userctx       User interact  handle (SPI handle)
 * 
 * \return On success, return the ATHW_EOK, negative (-ve) on failure 
 */
int athw_tpm_init(void *dev, void *iocb, void *userctx);

/*!
 * \fn  int athw_tpm_getrandom(void *dev, uint8_t *buf, uint32_t len) 
 *  
 * \brief   Get random number
 * 
 * \author rocke (2023-10-26) 
 *  
 * \code 
 * int rc; 
 * ATHW_TPM_DEV dev; 
 * SPI_Handle_t ctx; 
 * uint8_t message[1024] = {0, };  
 *  
 * rc = athw_tpm_init(&dev, (void *)IO_Cb, &ctx); 
 * if(rc != 0) { 
 *      goto exit; 
 * } 
 *  
 * ret = athw_tpm_getrandom((void *)&ctx, message, sizoef message); 
 * if(ret != 0) { 
 *      goto exit; 
 * } 
 *  
 * \endcode 
 * 
 * \param dev    Device structure handle
 * \param buf    Byte buffer that used to store the random number
 * \param len    size of buffer
 * 
 * \return On success, return the ATHW_EOK, negative (-ve) on failure 
 */
int athw_tpm_getrandom(void *dev, uint8_t *buf, uint32_t len);



int athw_tpm_encrypt_decrypt(void *dev, WOLFTPM2_KEY *key, const uint8_t *in,
                             uint8_t *out, uint32_t io_sz,
                             uint8_t *iv, uint32_t iv_sz, int is_decrypt);
/**
 * @brief Vendor specific TPM command and it used to enable 
 *        other restricted TPM commands
 * 
 * @author rocke (2023-10-26)
 * 
 * @param dev          TPM device handle structure
 * @param command_code vendor command code
 * @param flag         To enable, speicfic the non-zero values 
 * 
 * @return On success, return 0, negative (-ve) on failure 
 */
int athw_tpm_set_command(void *dev, TPM_CC command_code, int flag);


int athw_tpm_enc_dec_block(void *dev, WOLFTPM2_KEY *key, 
                           const uint8_t *in, uint8_t *out,uint8_t io_sz, 
                           uint8_t *iv, uint32_t iv_sz,
                           int is_decrypt);


int athw_tpm_set_auth_handle(void *_dev, int index, const WOLFTPM2_HANDLE *handle);



int athw_tpm_set_auth_password(void *dev, int index, const TPM2B_AUTH *auth);

/**
 * Set the TPM Authorization slot using the serveral parameter
 * 
 * @author rocke (2023-10-27)
 * 
 * @param _dev           
 * @param index          
 * @param session_handle 
 * @param auth           
 * @param session_attr   
 * @param name           
 * 
 * @return int 
 */
int athw_tpm_set_auth(void *_dev, int index, TPM_HANDLE session_handle,
                      const TPM2B_AUTH *auth,
                      TPMA_SESSION session_attr, 
                      const TPM2B_NAME *name);



int athw_get_key_template_symmetric(TPMT_PUBLIC *key, int keybits, TPM_ALG_ID mode, 
                                    int is_sign, int is_decrypt);


int athw_tpm_createkey(void *handle, const uint8_t *auth, int authsz);

int athw_tpm_loadkey(void *handle);

int athw_tpm_create_and_load_key(void *handle, const byte *auth, int authsz);


int athw_tpm_start_session(void *session, TPM_SE type, int cipheralg);

int ATHW_GetKeyTemplate_RSA_SRK(TPMT_PUBLIC* publicTemplate);
int ATHW_GetKeyTemplate_ECC_SRK(TPMT_PUBLIC* publicTemplate);

int ATHW_CreateSRK(ATHW_DEV* dev, ATHW_KEY* srkKey, TPM_ALG_ID alg,
    const byte* auth, int authSz);

int ATHW_CreatePrimaryKey(ATHW_DEV* dev, ATHW_KEY* key,
    TPM_HANDLE primaryHandle, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz);

int ATHWTPM2_EncryptSecret(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* tpmKey,
    TPM2B_DATA *data, TPM2B_ENCRYPTED_SECRET *secret,
    const char* label);

int ATHW_TPM2_KDFa(
    TPM_ALG_ID   hashAlg,   /* IN: hash algorithm used in HMAC */
    TPM2B_DATA  *keyIn,     /* IN: key */
    const char  *label,     /* IN: a 0-byte terminated label used in KDF */
    TPM2B_NONCE *contextU,  /* IN: context U (newer) */
    TPM2B_NONCE *contextV,  /* IN: context V */
    BYTE        *key,       /* OUT: key buffer */
    UINT32       keySz      /* IN: size of generated key in bytes */
);

int ATHWTPM2_StartSession(ATHW_DEV* dev, ATHW_SESSION* session,
    ATHW_KEY* tpmKey, ATHW_HANDLE* bind, TPM_SE sesType,
    int encDecAlg);

int ATHWPM2_NVStoreKey(ATHW_DEV* dev, TPM_HANDLE primaryHandle,
    ATHW_KEY* key, TPM_HANDLE persistentHandle);

#ifdef _cplusplus
}
#endif

#endif
