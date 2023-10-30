
#include "bench_test.h"
#include "athw_tpm_wrap.h"

int getPrimaryStoragekey(ATHW_DEV* pDev, ATHW_KEY* pStorageKey,
    TPM_ALG_ID alg)
{
    int rc;
    TPM_HANDLE handle;

    if (alg == TPM_ALG_RSA)
        handle = TPM2_DEMO_STORAGE_KEY_HANDLE;
    else if (alg == TPM_ALG_ECC)
        handle = TPM2_DEMO_STORAGE_EC_KEY_HANDLE;
    else {
        printf("Invalid SRK alg %x\r\n", alg);
        return BAD_FUNC_ARG;
    }

    /* See if SRK already exists */
    rc = ATHW_ReadPublicKey(pDev, pStorageKey, handle);
    if (rc != 0) {
        /* Create primary storage key */
        rc = ATHW_CreateSRK(pDev, pStorageKey, alg,
            (byte*)gStorageKeyAuth, sizeof(gStorageKeyAuth)-1);
    #if 0 //ndef WOLFTPM_WINAPI
        if (rc == TPM_RC_SUCCESS) {
            /* Move storage key into persistent NV */
            rc = ATHW_NVStoreKey(pDev, TPM_RH_OWNER, pStorageKey, handle);
        }
    #endif
    }
    else {
        /* specify auth password for storage key */
        pStorageKey->handle.auth.size = sizeof(gStorageKeyAuth)-1;
        XMEMCPY(pStorageKey->handle.auth.buffer, gStorageKeyAuth,
                pStorageKey->handle.auth.size);
    }
    if (rc != 0) {
        printf("Loading SRK: Storage failed 0x%x: %s\r\n", rc,
            TPM2_GetRCString(rc));
        return rc;
    }
    printf("Loading SRK: Storage 0x%x (%d bytes)\r\n",
        (word32)pStorageKey->handle.hndl, pStorageKey->pub.size);
    return rc;
}

