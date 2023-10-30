/********************************************************************************
 * Copyright (C) 2020 by Trustkey                                               * 
 * This file is part of  Project                                                *   
 * This software contains confidential information of TrustKey Co.,Ltd.         *
 * and unauthorized distribution of this software, or any portion of it, are    *
 * prohibited.                                                                  *
 ********************************************************************************/

/**
 * @file bench_aes.c
 * AES Encrypt and Decrypt
 *
 * @anchor LEON_SYSTEM
 * @author Leon, (c) Trustkey
 * @version Draft 
 * @date 2023-10-27
 * @bug No known bugs.
 * @note 
 * 
 * @copyright Copyright 2020 Trustkey. All rights reserved*
 */
 
#include "stm32l4xx_hal.h"
#include "tpm2_wrap.h"
#include "tpm_errno.h"
#include "athw_tpm_wrap.h"
#include "log.h"

static const char gStorageKeyAuth[] = "ThisIsMyStorageKeyAuth";
static const char gAiKeyAuth[] =      "ThisIsMyAiKeyAuth";
static const char gKeyAuth[] =        "ThisIsMyKeyAuth";
static const char gKeyAuthAlt[] =     "ThisIsMyKeyAltAuth";
static const char gUsageAuth[] =      "ThisIsASecretUsageAuth";
static const char gNvAuth[] =         "ThisIsMyNvAuth";
static const char gXorAuth[] =        "ThisIsMyXorAuth";

/* Configuration */
#define TPM2_BENCH_DURATION_SEC         1
#define TPM2_BENCH_DURATION_KEYGEN_SEC  15
static int gUseBase2 = 1;

void bench_stats_start(int* count, double* start)
{
    *count = 0;
    *start = HAL_GetTick();
}

int bench_stats_check(double start, int* count, double maxDurSec)
{
    (*count)++;
    return ((HAL_GetTick() - start) < maxDurSec);
}

/* countSz is number of bytes that 1 count represents. Normally bench_size,
 * except for AES direct that operates on AES_BLOCK_SIZE blocks */
void bench_stats_sym_finish(const char* desc, int count, int countSz,
    double start)
{
    double total, persec = 0, blocks = count;
    const char* blockType;

    total = HAL_GetTick() - start;

    /* calculate actual bytes */
    blocks *= countSz;

    /* base 2 result */
    if (gUseBase2) {
        /* determine if we should show as KB or MB */
        if (blocks > (1024 * 1024)) {
            blocks /= (1024 * 1024);
            blockType = "MB";
        }
        else if (blocks > 1024) {
            blocks /= 1024; /* make KB */
            blockType = "KB";
        }
        else {
            blockType = "bytes";
        }
    }
    /* base 10 result */
    else {
        /* determine if we should show as kB or mB */
        if (blocks > (1000 * 1000)) {
            blocks /= (1000 * 1000);
            blockType = "mB";
        }
        else if (blocks > 1000) {
            blocks /= 1000; /* make kB */
            blockType = "kB";
        }
        else {
            blockType = "bytes";
        }
    }

    /* calculate blocks per second */
    if (total > 0) {
        persec = (1 / total) * blocks;
    }

//  /* format and print to terminal */
//  printf("%-16s %d %s took %d ms, %d %s/s\r\r\n",
//      desc, blocks, blockType, total, persec, blockType);
    
    printf("%-16s %5.0f %s took %5.3f seconds, %8.3f %s/s \r\r\n",
        desc, blocks, blockType, total, persec, blockType);
}


int bench_sym_aes(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* storageKey,
    const char* desc, int algo, int keyBits, const byte* in, byte* out,
    word32 inOutSz, int isDecrypt, double maxDuration)
{
    int rc = ATHW_EOK;
    int count = 0L;
    uint32_t start;
    TPMT_PUBLIC pub_template;
    ATHW_KEY aeskey;
        
    TPM_ALG_ID paramEncAlg = TPM_ALG_CFB;
    
    athwtpm2_keyhnd_t hndl = {
        .dev = dev,
        .key = &aeskey,
        .pub = &pub_template,
        .parent = &storageKey->handle,
        .blob = NULL
    };
    
    athw_memzero_s(&aeskey, sizeof aeskey);
    rc = athw_get_key_template_symmetric(&pub_template, keyBits,algo,
                                         YES, YES);
    if(rc != 0) {
        tr_log("Template key get fail");
        goto exit;
    }

    rc = athw_tpm_create_and_load_key((void *)&hndl,
                                      (uint8_t *)gUsageAuth,
                                      sizeof(gUsageAuth) - 1);
    
    
    if ((rc & TPM_RC_MODE) == TPM_RC_MODE || (rc & TPM_RC_VALUE) == TPM_RC_VALUE) {
        tr_log("Benchmark symmetric %s not supported!\r\n", desc);
        rc = 0; goto exit;
    }
    else if (rc != 0)  {
        tr_log("Key create and load fail !!! (0x%x)",rc);
        goto exit;
    }
    
    bench_stats_start(&count, &start);
    
    do {
        rc = athw_tpm_encrypt_decrypt(dev, &aeskey, in, out, inOutSz, NULL, 0, isDecrypt);
        if (rc == TPM_RC_COMMAND_CODE) {
            tr_log("unavilavle the encrypt and decrypt ");
            break;
        }
    } while (bench_stats_check(start, &count, maxDuration));
    
    bench_stats_sym_finish(desc, count, inOutSz, start);
    
    // TODO : TPM2 Unload Handle implemntatin 

    

exit:
    
    return rc;

}


