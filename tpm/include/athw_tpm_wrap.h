#ifndef _ATHW_TPM_WRAP_H
#define _ATHW_TPM_WRAP_H

#ifdef _cplusplus
extern "C" {
#endif

#include "tpm2_wrap.h"

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


int athw_tpm_set_auth(void *_dev, int index, TPM_HANDLE session_handle,
                      const TPM2B_AUTH *auth,
                      TPMA_SESSION session_attr, 
                      const TPM2B_NAME *name);





#ifdef _cplusplus
}
#endif

#endif