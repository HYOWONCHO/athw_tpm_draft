/********************************************************************************
 * Copyright (C) 2020 by Trustkey                                               * 
 * This file is part of  Project                                                *   
 * This software contains confidential information of TrustKey Co.,Ltd.         *
 * and unauthorized distribution of this software, or any portion of it, are    *
 * prohibited.                                                                  *
 ********************************************************************************/

/**
 * @file tpm_spi_handle.c
 * @anchor LEON_SYSTEM
 * @author Leon, (c) Trustkey
 * @version Draft
 *
 * TPM SPI interface and interaction 
 *
 * @date 2023-10-12
 * @bug No known bugs.
 * @note 
 * 
 * @copyright Copyright 2020 Trustkey. All rights reserved
 *
 */

#include "tpm_spi_handle.h"
#include "util_time.h"
//static int athw_tpm_spi_write_bytes(void *handle, u32 addr, u16 len, const u8 *out);
//static int athw_tpm_spi_write32(void *handle, u32 addr, u32 value);
//static int athw_tpm_spi_read_bytes(void *handle, u32 addr, u16 len, const u8 *in);
//static int athw_tpm_spi_read32(void *handle, u32 addr, u32 *result);

int athw_tpm_spi_write_bytes(void *handle, u32 addr, u16 len, const u8 *out)
{
    return athw_tpm_spi_xfer(handle,addr,out, NULL,len);
}


int athw_tpm_spi_write32(void *handle, u32 addr, u32 value)
{
    __le32 le_value = cpu_to_le32(value);
    //__le32 le_value = value;
    return athw_tpm_spi_write_bytes(handle, addr, sizeof value, (u8 *)&le_value);
}

int athw_tpm_spi_read_bytes(void *handle, u32 addr, u16 len,  u8 *in)
{
    return athw_tpm_spi_xfer(handle,addr,NULL, (u8 *)in,len);
}


int athw_tpm_spi_read32(void *handle, u32 addr, u32 *result)
{
    __le32 le_ret = 0UL;
    int ret;
    
    ret = athw_tpm_spi_read_bytes(handle, addr, sizeof(u32), (u8 *)&le_ret);
    if (!ret) {
        *result = le32_to_cpu(le_ret);
    }
    
    return ret;
}

int __weak athw_tpm_open(void *priv)
{
    int ret = ATHW_EOK;
    //int is_open  = 0L;
    
    tpm_spi_handle_t *handle = (tpm_spi_handle_t *)priv;
    
    if( handle == NULL ) {
        tr_log("param point to null");
        ret = -ATHW_ENULLP;
        goto athw_release;
    }
    

    if( ((athw_dev_t *)handle->dev)->is_open ) {
        tr_log("device already open");
        ret = -ATHW_EBUSY;
        goto athw_release;
    }
    
    

athw_release:
    return ret;
}

int __weak athw_tpm_close(void *priv)
{
    int ret = ATHW_EOK;
    
    if( !priv ) {
        ret = -ATHW_ENULLP;
        goto athw_release;
    }

athw_release:
    return ret;
}

int __weak athw_tpm_recv(void *priv, const uint8_t *buf, size_t size)
{
    int ret = ATHW_EOK;
    
    if( !priv ) {
        ret = -ATHW_ENULLP;
        goto athw_release;
    }
    
athw_release:
    return ret;    
}

int __weak athw_tpm_send(void *priv, const uint8_t *buf, size_t len)
{
    int ret = ATHW_EOK;
    //tpm_spi_handle_t *dev = (tpm_spi_handle_t *)priv;
    athw_dev_t *dev = (athw_dev_t *)priv;
    u8 status;
    size_t burstcnt, wr_size, sent = 0;
    u8 data = TPM_STS_GO;
    
    if( !dev ) {
        ret = -ATHW_ENODEV;
        tr_log("can't found the device");
        goto athw_release;
    }
    
    if( len <= 0 ) {
        ret = -ATHW_ESZEROL;
        tr_log("send size zero");
        goto athw_release;
    }

    ret = athw_tpm_request_locality(dev, 0);
    if( ret < 0 ) {
        ret = -ATHW_EBUSY;
        tr_log("tpm device busy");
        goto athw_release;
    }
    
    ret = athw_tpm_get_status(dev, &status);
    if( ret ) {
        goto athw_release;
    }
    
    // Device is not ready 
    if( !(status & TPM_STS_COMMAND_READY) ) {
        ret = athw_tpm_ready(dev);
        if( ret ) {
            tr_log("can not cancel previous device operation");
            goto athw_release;
        }
        
        ret = athw_tpm_wait_for_stat(dev, TPM_STS_COMMAND_READY, 1000, &status);
        if( ret ) {
            tr_log("device not ready");
            goto athw_release;
        }
    }
    
    while( len > 0 ) {
        ret  = athw_tpm_get_burstcount(dev, &burstcnt);
        if( ret ) {
            goto athw_release;
        }
        
        wr_size = min(len, burstcnt);
        ret = dev->phy_ops->write_bytes(dev, TPM_DATA_FIFO(dev->locality),
                                        wr_size, buf +sent);
        if(ret < 0) {
            goto athw_release;
        }
        
        ret = athw_tpm_wait_for_stat(dev, TPM_STS_VALID, dev->timeout_c,&status);
        if( ret ) {
            goto athw_release;
        }
        
        sent += wr_size;
        len -= wr_size;
        // make sure expects more data
        if( len && !(status & TPM_STS_DATA_EXPECT) ) {
            ret = -ATHW_EIO;
            goto athw_release;
        }

        
    }
    
    // final checking that everything ok
    ret = athw_tpm_wait_for_stat(dev, TPM_STS_VALID, dev->timeout_c,&status);
    if( ret ) {
        goto athw_release;
    }
    
    if( status & TPM_STS_DATA_EXPECT ) {
        ret = -ATHW_EIO;
        goto athw_release;
    }
    
    ret = dev->phy_ops->write_bytes(dev, TPM_STS(dev->locality), 1, &data);
    if( ret ) {
        goto athw_release;
    }
    
    return sent;


athw_release:
    
    athw_tpm_ready(dev);
    athw_tpm_release_locality(dev, dev->locality);
    return ret;    
}

int __weak athw_tpm_cleaup(void *priv)
{
    int ret = ATHW_EOK;
    
    if( !priv ) {
        ret = -ATHW_ENULLP;
        goto athw_release;
    }
    
athw_release:
    return ret;
}


/**
 * @fn int athw_tpm_spi_handle_init(void *priv) 
 * @brief SPI interface init. 
 * 
 * @author rocke (2023-10-12) 
 *  
 * 
 * @param priv   SPI handle 
 * 
 * @return on Success, return 0, otherwise return  nagitive  
 *         value
 */
int athw_tpm_spi_handle_init(void *priv)
{
    int ret = ATHW_EOK;
    tpm_spi_handle_t *h = (tpm_spi_handle_t *)priv;
    int tick_start, tick_stop;
    
    
    if( h == NULL ) {
        ret = -ATHW_ENULLP;
        goto athw_release;
    }    
   
    //athw_tpm_reset();
    
    //delay_ms(30);
    
    h->ops.if_open = athw_tpm_open;
    h->ops.if_close = athw_tpm_close;
    h->ops.if_send = athw_tpm_send;
    h->ops.if_recv = athw_tpm_recv;
    h->ops.if_cleanup = athw_tpm_cleaup;
    
    h->phy_ops->read_bytes = athw_tpm_spi_read_bytes;
    h->phy_ops->read32 = athw_tpm_spi_read32;
    h->phy_ops->write_bytes = athw_tpm_spi_write_bytes;
    h->phy_ops->write32 = athw_tpm_spi_write32;
    
    
    //h->dev.is_open = 0;
//
//  tr_log("phy_ops addr %p, %p , %p, %p, %p",
//         h->phy_ops,
//         h->phy_ops->read_bytes, h->phy_ops->read32,
//         h->phy_ops->write_bytes, h->phy_ops->write32);

athw_release:

    return ret;
}

/**
 * @fn void tpm_spi_handle_deinit(void *priv) 
 * @brief SPI interface de-init 
 * 
 * @author rocke (2023-10-12)
 * 
 * @param priv   SPI handle
 */
void athw_tpm_spi_handle_deinit(void *priv)
{

    HAL_GPIO_DeInit(TPM_GPIO_BASE, TPM_SPI_NSS);
    TPM_SPI_NSS_LOW;
    
    return;
    
    
    
}

/**
 * @fn int athw_tpm_spi_xfer(void *handle, u32 addr, const u8 *out, 
 *     u8 *in, u16 len)
 * 
 * @author rocke (2023-10-12)
 * 
 * @param handle 
 * @param addr      register address to read from
 * @param out       provided by caller
 * @param in        provided by caller
 * @param len       number of bytes to read 
 *  
 * @details Read len bytes from TPM register and put thme into 
 *          buffer (little-ATHW_Endian format, i.e first byte is put
 *          into buffer[0])
 *  
 * @note TPM is big-ATHW_Endian for multi-byte values. Multi-byte 
 *       values have to be swapped.
 * 
 * @return -ATHW_EIO on error, 0 on success 
 */
int athw_tpm_spi_xfer(void *handle, u32 addr, const u8 *out, u8 *in, u16 len)
{
    int ret = ATHW_EOK;
    int transfer_len;
    
    u32 flags = SPI_XFER_BEGIN;
    u8 tx_buf[MAX_SPI_FRAMESIZE + TPM_TIS_HEADER_SZ] = {0,};
    u8 rx_buf[MAX_SPI_FRAMESIZE + TPM_TIS_HEADER_SZ] = {0,};
    
    tpm_spi_handle_t *h_spi = (tpm_spi_handle_t *)handle;
    
    if( h_spi == NULL  ) {
       return -ATHW_ENULLP;
       
    }
    
    if( in && out ) {
        tr_log("can't do full duplex");
        return -ATHW_EINVAL;
    }

    if( len <= 0 ) {
        tr_log("length of zero");
        return -ATHW_ESZEROL;
    }
    __HAL_SPI_ENABLE(h_spi->handle);
    //if( flags & SPI_XFER_BEGIN ) {
        //tr_log("NSS Active  LOW");
        // Active low
    TPM_SPI_NSS_ACTIVE;
    
    //}
#if 0
    while( len ) {
        //tr_log();
        transfer_len = min_t(u16, len, MAX_SPI_FRAMESIZE);
    
        tx_buf[0] = (in ? BIT(7) : 0) | (transfer_len -1);
        //tr_log("transfer len : %d, txbuf[0] : 0x%x", transfer_len, tx_buf[0]);
        //tr_log("addr: 0x%x, addr>>8 : 0x%x", addr, addr >> 8);
        tx_buf[1] = 0xD4;
        tx_buf[2] = addr >> 8;
        tx_buf[3] = addr;
        
        memset((void *)&tx_buf[TPM_TIS_HEADER_SZ], 0x0, sizeof tx_buf - TPM_TIS_HEADER_SZ);
        memset((void *)rx_buf, 0x0, sizeof rx_buf); 

       //_buf_dump(tx_buf, "1 TX", 4);
 
        _athw_print_bin("TPM Header", tx_buf, transfer_len + TPM_TIS_HEADER_SZ);
        ret = HAL_SPI_TransmitReceive(h_spi->handle,
                                      tx_buf, rx_buf,
                                      transfer_len + TPM_TIS_HEADER_SZ,
                                      TPM_SPI_TMO_DURATION);
        
        _athw_print_bin("TPM Header Response", rx_buf,transfer_len + TPM_TIS_HEADER_SZ);
        if( ret != 0 ) {
            tr_log("spi request transfer failed(err: %d)", ret);
            ret = -ATHW_EIO;
            goto release_bus;
        }
        //_buf_dump(rx_buf, "1 RX", 4);
        //tr_log("check for tpm wait state");
        /* check for wait state */
        if( !(rx_buf[3] & 0x1) ) {
            int i;
            
            for(i = 0; i < TPM_WAIT_STATES; i++) {
                //delay_ms(30);
                memset(rx_buf, 0x00, sizeof rx_buf);
                ret = HAL_SPI_TransmitReceive(h_spi->handle,
                                              tx_buf, rx_buf, 
                                              1, TPM_SPI_TMO_DURATION);
                 //_buf_dump(rx_buf, "2 RX", 1);
                if( ret != 0 ) {
                    tr_log("wait state failed: %d", ret);
                    ret = -ATHW_EIO;
                    goto release_bus;
                }
                
                
                if( rx_buf[0] & 0x1 ) {
                    break;
                }
            }
            
            if( i == TPM_WAIT_STATES ) {
                tr_log("timeout on wait state");
                ret = -ATHW_ETIMEDOUT;
                goto release_bus;
            }
        }
        
        if( out ) {
            //delay_ms(30);
            memset(tx_buf, 0x0, sizeof tx_buf);
            memcpy(tx_buf, out, transfer_len);
            out += transfer_len;
            
            HAL_SPI_TransmitReceive(h_spi->handle, 
                                    tx_buf, rx_buf,
                                    transfer_len, TPM_SPI_TMO_DURATION);
        }
        
        
        if( in ) {
            //delay_ms(30);
            //memset(tx_buf, 0xFF, sizeof tx_buf);
            //tr_log();
            memset(rx_buf, 0x00, sizeof rx_buf);
            _athw_print_bin("IN TX", tx_buf, transfer_len);
            HAL_SPI_TransmitReceive(h_spi->handle, 
                                    tx_buf, rx_buf, 
                                    transfer_len, TPM_SPI_TMO_DURATION);
            _athw_print_bin("IN RX", rx_buf, transfer_len);

                        //_buf_dump(rx_buf, "In Rx", 16);
            //tr_log();

            memcpy(in, rx_buf, transfer_len);
            in += transfer_len;
        }
         
        len -= transfer_len;

        //HAL_SPI_TransmitReceive(h_spi->handle, tx_buf, rx_buf)
        
        //flags = SPI_XFER_END;
        
        //if( flags & SPI_XFER_END ) {
            //tr_log("NSS HIGH");
        //    TPM_SPI_NSS_DEACTIVE;
        //}
        
    }
#else
    transfer_len = min_t(u16, len, MAX_SPI_FRAMESIZE);

    tx_buf[0] = (in ? BIT(7) : 0) | (transfer_len -1);
    //tr_log("transfer len : %d, txbuf[0] : 0x%x", transfer_len, tx_buf[0]);
    //tr_log("addr: 0x%x, addr>>8 : 0x%x", addr, addr >> 8);
    tx_buf[1] = 0xD4;
    tx_buf[2] = addr >> 8;
    tx_buf[3] = addr;
    
    memset((void *)&tx_buf[TPM_TIS_HEADER_SZ], 0x0, sizeof tx_buf - TPM_TIS_HEADER_SZ);
    memset((void *)rx_buf, 0x0, sizeof rx_buf);
    
    if( out ) {
        //memset(tx_buf, 0x0, sizeof tx_buf);
        memcpy(&tx_buf[TPM_TIS_HEADER_SZ], out, len);
        //out += transfer_len;
        
        HAL_SPI_TransmitReceive(h_spi->handle, 
                                tx_buf, rx_buf,
                                transfer_len, TPM_SPI_TMO_DURATION);
    }
    
    
    if( in ) {
        memset(rx_buf, 0x00, sizeof rx_buf);
        memcpy(&tx_buf[TPM_TIS_HEADER_SZ], in, transfer_len);
        //_athw_print_bin("IN buff", in, len);
        _athw_print_bin("IN TX", tx_buf, TPM_TIS_HEADER_SZ + transfer_len);
        HAL_SPI_TransmitReceive(h_spi->handle, 
                                tx_buf, rx_buf, 
                                transfer_len, TPM_SPI_TMO_DURATION);
        _athw_print_bin("IN RX", rx_buf, transfer_len);
       
        memcpy(in, rx_buf, transfer_len);
        in += transfer_len;
    }
#endif
    
    
    
release_bus:
    
    __HAL_SPI_DISABLE(h_spi->handle);
    //if( ret < 0 ) {
        //tr_log("NSS HIGH");
    TPM_SPI_NSS_DEACTIVE;
    //}
    
    //

    return ret;
    
}

uint32_t athw_tpm_spi_frequency(uint32_t hz)
{
    uint32_t divisor = 0;
    uint32_t sysclk_tmp = SystemCoreClock;
    uint32_t baudRate;
    
    tr_log("System Core Clock : %d Hz", sysclk_tmp);
    
    while( sysclk_tmp > hz)
    {
        divisor++;
        sysclk_tmp= ( sysclk_tmp >> 1);
        
        if (divisor >= 7)
            break;
    }
    
    baudRate =((( divisor & 0x4 ) == 0 )? 0x0 : SPI_CR1_BR_2  )| 
            ((( divisor & 0x2 ) == 0 )? 0x0 : SPI_CR1_BR_1  )| 
            ((( divisor & 0x1 ) == 0 )? 0x0 : SPI_CR1_BR_0  );
    
    return baudRate;
}

