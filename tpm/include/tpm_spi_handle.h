/*
 * tpm_handle.h
 *
 *  Created on: 2023. 9. 12.
 *      Author: rocke
 */

#ifndef INCLUDE_TPM_HANDLE_H_
#define INCLUDE_TPM_HANDLE_H_


#ifdef __cplusplus
extern "C" {
#endif


#include "tpm_common.h"

/*! 
  \def MAX_SPI_FRAMESIZE
  SPI \a TX and \a RX buffer size 
  */
#define MAX_SPI_FRAMESIZE     64
#define TPM_TIS_HEADER_SZ      4

#define TPM_IOBUF_SZ                (1024)

#define TPM_IOSTATE_BUSY            (1<<0)
#define TPM_IOSTATE_IDLE            

/**
 * @def TPM_SPI_TMO_DURATION 
 * SPI Timeout duration 
 */
#define TPM_SPI_TMO_DURATION        250


#define TPM_GPIO_BASE               GPIOA
#define TPM_SPI_NSS                 GPIO_PIN_4
#define TPM_PIN_INT                 GPIO_PIN_3
#define TPM_PIN_RST                 GPIO_PIN_8

#define TPM_SPI_SPEED               24000000    // 24MHz ( support at up to 33MHz )

#define TPM_WAIT_STATES             100 /// Number of wait states to wait for
  
#define TPM_SPI_NSS_HIGH                                      \
  do {                                                        \
    HAL_GPIO_WritePin(TPM_GPIO_BASE, TPM_SPI_NSS, GPIO_PIN_SET);      \
  } while (0)
  
  
#define TPM_SPI_NSS_LOW                                       \
  do {                                                        \
    HAL_GPIO_WritePin(TPM_GPIO_BASE, TPM_SPI_NSS, GPIO_PIN_RESET);    \
  } while (0)
  
#define TPM_SPI_NSS_ACTIVE      TPM_SPI_NSS_LOW
#define TPM_SPI_NSS_DEACTIVE    TPM_SPI_NSS_HIGH








int athw_tpm_spi_handle_init(void *priv);
void athw_tpm_spi_handle_deinit(void *priv);
//int tpm_spi_xfer(void *handle, u32 addr, const u8 *out, u8 *in, u16 len);
int athw_tpm_spi_xfer(void *handle, u32 addr, const u8 *out, u8 *in, u16 len);
int athw_tpm_spi_write_bytes(void *handle, u32 addr, u16 len, const u8 *out);
int athw_tpm_spi_write32(void *handle, u32 addr, u32 value);
int athw_tpm_spi_read_bytes(void *handle, u32 addr, u16 len, u8 *in);
int athw_tpm_spi_read32(void *handle, u32 addr, u32 *result);
uint32_t athw_tpm_spi_frequency(uint32_t hz);
#ifdef __cplusplus
}
#endif



#endif /* INCLUDE_TPM_HANDLE_H_ */
