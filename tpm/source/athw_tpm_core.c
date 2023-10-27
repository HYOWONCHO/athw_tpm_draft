/********************************************************************************
 * Copyright (C) 2020 by Trustkey                                               * 
 * This file is part of  Project                                                *   
 * This software contains confidential information of TrustKey Co.,Ltd.         *
 * and unauthorized distribution of this software, or any portion of it, are    *
 * prohibited.                                                                  *
 ********************************************************************************/

/**
 * @file athw_tpm_core.c
 * ATHW TPM2 core operation
 *
 * @anchor LEON_SYSTEM
 * @author Leon, (c) Trustkey
 * @version Draft 
 * @date 2023-10-13
 * @bug No known bugs.
 * @note 
 * 
 * @copyright Copyright 2020 Trustkey. All rights reserved*
 */

#include "tpm_spi_handle.h"
#include "util_time.h"


static void athw_tpm_reset(void)
{
    HAL_GPIO_WritePin(GPIOA, GPIO_PIN_8, GPIO_PIN_SET);
    delay_ms(1);
    HAL_GPIO_WritePin(GPIOA, GPIO_PIN_8, GPIO_PIN_RESET);
}

static bool athw_tpm_dev_check_param_cb(athw_tpm_phy_ops_t *phy_ops)
{
//  tr_log("phy_ops addr %p, %p , %p, %p, %p",
//        phy_ops,
//        phy_ops->read_bytes, phy_ops->read32,
//        phy_ops->write_bytes, phy_ops->write32);
    
    if(!phy_ops || !phy_ops->read_bytes || !phy_ops->write_bytes ||
       !phy_ops->read32 || !phy_ops->write32) {
        return false;
    }
    
    return true;
}

static int athw_tpm_wait_init(void *dev, int loc)
{
    athw_dev_t *chip = (athw_dev_t *)dev;
    u32 start, stop;
    u8 status = 0;
    int ret = ATHW_EOK;
    
    tr_log("start");
    if (!chip) {
        tr_log("Device handle invalid");
        ret  = -ATHW_ENULLP;
        goto athw_release;
    }
    
    //tr_log();
    start = HAL_GetTick();
    stop = chip->timeout_b;
    tr_log("loc : %d", loc);
    do {
        delay_ms(TPM_TIMEOUT_MS);
        
        ret = chip->phy_ops->read_bytes((void *)chip->if_handle, 
                                        TPM_ACCESS(loc),1,  &status);
        
        tr_log("Wait Staus : %d, ret %d", status, ret);
        if (ret) {
            break;
        }
        
        if (status & TPM_ACCESS_VALID) {
            tr_log("TPM Access Valid");
            ret = ATHW_EOK;
            goto athw_release;
        }
    } while (HAL_GetTick() - start < stop);

    ret = -ATHW_EIO;
athw_release:        
    
    tr_log("done");
    return ATHW_EOK;
}


int athw_tpm_get_desc(void *dev, char *buf, int size)
{
    athw_dev_t *chip = (athw_dev_t *)dev;

    if (size < 80)
        return -ATHW_ENOSPC;

    return snprintf(buf, size,
            "%s v2.0: VendorID 0x%04x, DeviceID 0x%04x, RevisionID 0x%02x [%s]",
            "ATHW Module", chip->vend_dev & 0xFFFF,
            chip->vend_dev >> 16, chip->rid,
            (chip->is_open ? "open" : "closed"));
}


/**
 * @fn athw_tpm_check_locality - Check the currently TPM 
 *     locality
 * 
 * @author rocke (2023-10-16)
 * 
 * @param loc     loacality
 * 
 * @return bool If locality is matched, return the true
 */
bool athw_tpm_check_locality(void *dev, int loc)
{
    u8 locality = 0;
    int ret  = ATHW_EOK;
    athw_dev_t *phy = (athw_dev_t *)dev;

    // TO DO : As later, implement a callback like the Kernel style 
    //while (1) {
        ret = phy->phy_ops->read_bytes((void *)phy->if_handle, TPM_ACCESS(loc), 1, &locality);
        //delay_ms);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       
    //}
    if (ret != ATHW_EOK) {
        tr_log("TPM %d Access fail with(%d)!!!", loc, ret);
        return false;
    }

    //tr_log("check locality : %d", locality);
    if ((locality & (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID |
        TPM_ACCESS_REQUEST_USE)) ==
        (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) {
        phy->locality = loc;
        return true;
    }
    
    
    return false;
    
}

int athw_tpm_request_locality(void *dev, int loc)
{
    athw_dev_t *handle = (athw_dev_t *)dev;
    u8 buf = TPM_ACCESS_REQUEST_USE;
    uint32_t start, stop;
    int ret = ATHW_EOK;
    
    if (athw_tpm_check_locality(dev, loc)) {
        return ATHW_EOK;
    }
    
    ret = handle->phy_ops->write_bytes((void *)handle->if_handle, TPM_ACCESS(loc), 1, &buf);
    if (ret != ATHW_EOK) {
        tr_log("Device Write Access Fail %d", ret);
        return ret;
    }
    
    start = HAL_GetTick();
    stop = handle->timeout_a;
    
    do {
        if (athw_tpm_check_locality(dev, loc)) {
            return 0;
        }

        delay_ms(TPM_TIMEOUT_MS);
    }while (HAL_GetTick() - start < stop);
    
    return -1;
}

/**
 * @fn int athw_tpm_get_status(void *dev, u8 *status) 
 *  
 * @brief Device status check 
 * 
 * @author rocke (2023-10-16)
 * 
 * @param dev    Device handle 
 * @param status Status value regards to TPM device 
 * 
 * @return ATHW_EOK on success, negative on failure(-ne) 
 */
int athw_tpm_get_status(void *dev, u8 *status)
{
    athw_dev_t *handle = (athw_dev_t *)dev;
    
    if (handle == NULL) {
        return -ATHW_ENODEV;
    }

    if (handle->locality < 0) {
        return -ATHW_EINVAL;
    }
    
    handle->phy_ops->read_bytes(dev, TPM_STS(handle->locality), 1, status);
    if ((*status &  TPM_STS_READ_ZERO)) {
        tr_log("return invalid status");
        return -ATHW_EINVAL;
    }

    
    return ATHW_EOK;
}

/**
 * @fn int athw_tpm_ready(void *dev) 
 * @brief Cancel panding command and get the device on a ready 
 *        state
 * 
 * @author rocke (2023-10-16)
 * 
 * @param dev    Device handle
 * 
 * @return ATHW_EOK on success, -ne 
 */
int athw_tpm_ready(void *dev)
{
    int ret = ATHW_EOK;
    athw_dev_t *handle = (athw_dev_t *)dev;
    u8 data = TPM_STS_COMMAND_READY;
    
    if (handle == NULL) {
        return -ATHW_ENODEV;
    }
    
    ret = handle->phy_ops->write_bytes(dev, TPM_STS(handle->locality),1 , &data);
    return ret;
}

/**
 * @fn nt athw_tpm_wait_for_stat(void *dev, u8 mask, uint32_t 
 *     timeout, u8 *status)
 *  
 * @brief  wait for TPM to become ready
 * 
 * @author rocke (2023-10-16)
 * 
 * @param dev     Device handle
 * @param mask    Filter mask
 * @param timeout Retries timeout 
 * @param status  Currently status 
 * 
 * @return ATHW_EOK on success, -ne 
 */
int athw_tpm_wait_for_stat(void *dev, u8 mask, uint32_t timeout, u8 *status)
{
    int ret = ATHW_EOK;
    uint32_t start = HAL_GetTick();
    uint32_t stop = timeout;
    
    do {
        delay_ms(TPM_TIMEOUT_MS);
        ret = athw_tpm_get_status(dev, status);
        if (ret) {
            return ret;
        }
        
        if ((*status & mask) == mask) {
            return ATHW_EOK;
        }

        
    } while (HAL_GetTick() - start < stop);
    
    return -ATHW_ETIMEDOUT;
}

/**
 * @fn int athw_tpm_get_burstcount(void *dev, size_t *count) 
 * @brief Obtain the \a burstcount for the data FIFO
 * 
 * @author rocke (2023-10-16)
 * 
 * @param dev    Device handle
 * @param count  Burstcount buffer
 * 
 * @return ATHW_EOK on success, -ve on failure
 */
int athw_tpm_get_burstcount(void *dev, size_t *count)
{
    athw_tpm_phy_ops_t  *phy_ops = ((athw_dev_t *)dev)->phy_ops;
    uint32_t tm_start, tm_stop;
    u32 burstcnt;
    
    
    if ( !dev || !phy_ops) {
        return -ATHW_ENULLP;
    }
    
    if ( ((athw_dev_t *)dev)->locality < 0 ) {
        return -ATHW_EINVAL;
    }
    
    // wait burst count 
    tm_start = HAL_GetTick();
    tm_stop = ((athw_dev_t *)dev)->timeout_a;
    
    do {
        phy_ops->read32(dev, TPM_STS(((athw_dev_t *)dev)->locality), &burstcnt);
        *count = (burstcnt >> 8) & 0xFFFF;
        if (*count) {
            return ATHW_EOK;
        }
    }while (HAL_GetTick() - tm_start < tm_stop);

    return -ATHW_ETIMEDOUT;

    
    
}

int athw_tpm_release_locality(void *dev, int loc)
{
    athw_dev_t *h_dev = (athw_dev_t *)dev;
    u8 buf = TPM_ACCESS_ACTIVE_LOCALITY;
    int ret;
    
    if (h_dev->locality < 0) {
        return ATHW_EOK;
    }
    
    ret = h_dev->phy_ops->write_bytes(dev, TPM_ACCESS(loc), 1, &buf);
    h_dev->locality = -1;
    
    return ret;

    
}

/**
 * @fn int athw_tpm_dev_init(void *dev) 
 * @brief Initialize the TPM device and configturation 
 * 
 * @author rocke (2023-10-16)
 * 
 * @param dev   device handle 
 * 
 * @return 0 on success, negative (-ve) on faliure
 */
int athw_tpm_dev_init(void *dev)
{
    extern SPI_HandleTypeDef hspi1;
    athw_dev_t *chip  = (athw_dev_t *)dev;
    
    static tpm_spi_handle_t spi_handle;
    static athw_tpm_phy_ops_t phyops;
    
 
    int ret;

    uint32_t tmp;
    
    memset(&spi_handle, 0x0, sizeof spi_handle);
    memset(&phyops, 0x0, sizeof phyops);
    //tr_log("%s start");
    athw_tpm_reset();

    spi_handle.handle = &hspi1;
    chip->if_handle = &spi_handle;
    chip->phy_ops = chip->if_handle->phy_ops = &phyops;
    chip->locality = 0;
    
    athw_tpm_spi_handle_init((void *)chip->if_handle);
    
    //tr_log("phy ops adress :0x%x" , &phyops);
    if(!athw_tpm_dev_check_param_cb(chip->phy_ops)) {
        tr_log("Bus operations not define");
        return -ATHW_EINVAL;
    }
    
   
    
    chip->timeout_a = TIS_SHORT_TIMEOUT_MS;
    chip->timeout_b = TIS_LONG_TIMEOUT_MS;
    chip->timeout_c = TIS_SHORT_TIMEOUT_MS;
    chip->timeout_d = TIS_SHORT_TIMEOUT_MS;

   // tr_log("tpm wait !!!");
    ret = athw_tpm_wait_init(dev, chip->locality);
    if (ret) {
        tr_log("no device found %d", ret);
        return ret;
    }
//
//  while (1) {
//      ret = athw_tpm_request_locality(dev, 0);
//      tr_log("Request locality fail %d ", ret);
//      delay_ms(500);
//  }
    
    //tr_log("request locality for 0") ;
    ret = athw_tpm_request_locality(dev, 0);
    if (ret) {
        tr_log("Request locality fail %d ", ret);
        return ret;
    }

    //delay_ms(1000);

    
    tr_log("Request locality done %d", ret);
    chip->phy_ops->read32((void *)chip->if_handle, TPM_INT_ENABLE(chip->locality), (u32 *)&tmp);
      tmp |= TPM_INTF_CMD_READY_INT | TPM_INTF_LOCALITY_CHANGE_INT |
           TPM_INTF_DATA_AVAIL_INT | TPM_INTF_STS_VALID_INT;
    tmp &= ~TPM_GLOBAL_INT_ENABLE;
    chip->phy_ops->write32((void *)chip->if_handle, TPM_INT_ENABLE(chip->locality), tmp);

    chip->phy_ops->read_bytes((void *)chip->if_handle, TPM_RID(chip->locality), 1, &chip->rid);
    chip->phy_ops->read32((void *)chip->if_handle, TPM_DID_VID(chip->locality), (u32 *)&chip->vend_dev);
    
    chip->is_open = 1;
    
    tr_log("Vendor ID  0x%04x, Device ID 0x%04x Revision ID 0x%02x",
           chip->vend_dev & 0xFFFF, chip->vend_dev >> 16, chip->rid);
    
    //tr_log("%s end");

    return athw_tpm_release_locality(dev, chip->locality);


}



