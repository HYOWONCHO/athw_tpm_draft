/********************************************************************************
 * Copyright (C) 2020 by Trustkey                                               * 
 * This file is part of  Project                                                *   
 * This software contains confidential information of TrustKey Co.,Ltd.         *
 * and unauthorized distribution of this software, or any portion of it, are    *
 * prohibited.                                                                  *
 ********************************************************************************/

/**
 * @file tpm_common.c
 * TPM command 
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

#include "tpm_common.h"



/*
 * Allow unaligned memory access.
 *
 * This routine is overridden by architectures providing this feature.
 */
void __weak athw_allow_unaligned(void)
{
}


/**
 * Get TPM command size 
 * 
 * @author rocke (2023-10-13)
 * 
 * @param command TPM command 
 * 
 * @return command size for TPM command 
 */
int athw_tpm_command_size(const void *command)
{
    const size_t command_size_offset = 2;
    
    if (command == NULL) {
        tr_log("OOPS point to Nill");
        return -ATHW_ENULLP;
    }

    return get_unaligned_be32(command + command_size_offset);
}




/**
 * Transfer the TPM command, and then return response retrun 
 * code 
 * 
 * @author rocke (2023-10-13)
 * 
 * @param cmd     Marsharled command stream
 * @param resp    TPM response buffer
 * @param[in]  len_ptr output buffer size 
 * @param[out] len_ptr response length 
 *  
 * @note If \a "resp" parameter is NULL, caller dose not care 
 *       about it. \n \a "len_ptr" parameter is a bidirectional.
 * 
 * @return Return code for TPM repsonse 
 */
int athw_tpm_xfer_command(const void *cmd, void *resp, size_t *len_ptr)
{
    int ret;
    u8 response_buffer[COMMAND_BUFFER_SIZE];
    size_t response_length;
    int i;
    uint32_t size;
    
    uint32_t count, ordinal;
    
    if (resp) {
        response_length = *len_ptr;
    }
    else {
        resp = response_buffer;
        response_length = sizeof response_buffer;
    }
    
    size = athw_tpm_command_size(cmd);
    
    if (size > COMMAND_BUFFER_SIZE) {
        ret = -ATHW_E2BIG;
        tr_log("size : %d ", size);
        goto athw_release;
    }
    
    _buf_dump(cmd, "ATHW Request", size);
    
    count = get_unaligned_be32(cmd + TPM_CMD_COUNT_BYTE);
    ordinal = get_unaligned_be32(cmd + TPM_CMD_ORDINAL_BYTE);
    
    if (count == 0) {
        tr_log("No Data");
        ret = -ATHW_ENODATA;
        goto athw_release;
    }
    
    if (count > size) {
        tr_log("count too big %x %zx", count, size);
        ret = -ATHW_E2BIG;
        goto athw_release;
    }
    
    

    
athw_release:
    
    return ret;
    
    
}


                                       
