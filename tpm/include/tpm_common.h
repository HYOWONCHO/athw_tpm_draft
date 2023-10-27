#ifndef _TPM_COMMON_H
#define _TPM_COMMON_H




#ifdef __cplusplus
extern "C" {
#endif

#include "tpm_types.h"
#include "stm32l4xx_hal.h"
//#include "tpm_spi_handle.h"

/**
 * @struct athw_tpm_phy_ops_t tpm_common.h 
 *         "tpm/include/tpm_common.h"
 *  
 * @brief ATHW TPM device bus operation 
 * 
 * @author rocke (2023-10-13)
 */
typedef struct _athw_tpm_phy_ops_t {
    /** 
     * read_bytes() - Read a number of bytes from the device
     *
     * @udev:   TPM device
     * @addr:   offset from device base
     * @len:    len to read
     * @result: data read
     *
     * @return: 0 on success, negative on failure
     */
    int (*read_bytes)(void  *udev, u32 addr, u16 len,
              u8 *result);
    /** 
     * write_bytes() - Read a number of bytes from the device
     *
     * @udev:   TPM device
     * @addr:   offset from device base
     * @len:    len to read
     * @value:  data to write
     *
     * @return: 0 on success, negative on failure
     */
    int (*write_bytes)(void  *udev, u32 addr, u16 len,
               const u8 *value);
    /** 
     *  read32() - Read a 32bit value of the device
     *
     * @udev:   TPM device
     * @addr:   offset from device base
     * @result: data read
     *
     * @return: 0 on success, negative on failure
     */
    int (*read32)(void  *udev, u32 addr, u32 *result);
    /** 
     *  write32() - write a 32bit value to the device
     *
     * @udev: TPM device
     * @addr: offset from device base
     * @src:  data to write
     *
     * @return: 0 on success, negative on failure
     */
    int (*write32)(void  *udev, u32 addr, u32 src);
}athw_tpm_phy_ops_t;


/**
 * @struct athw_spi_tpm_ops_t tpm_spi_handle.h 
 *         "tpm/include/tpm_spi_handle.h"
 * @brief ATHW Crypto operation  
 * 
 * @author rocke (2023-10-13)
 */
typedef struct _athw_tpm_ops_t {

    /**
     * @fn int (*if_open)(void pirv) -  Session open 
     * 
     * @author rocke (2023-10-13)
     * 
     * @param pirv   SPI handle 
     * 
     * @return on Success, return EOK 
     */
    int (*if_open)(void *pirv);
    
    /**
     * @fn int (*if_close)(void *priv - Session close
     * 
     * @author rocke (2023-10-13)
     */
    int (*if_close)(void *priv);
    
    /**
     * @fn int (*if_send)(void *priv, const uint8_t *txbuf, size_t 
     *     tx_size);
     * @brief Send mashaled data to TPM device 
     *  
     * @param priv  Interface handle 
     * @param buf   Buffer of the data to send 
     * @param size  Data of size to send 
     * 
     * @author rocke (2023-10-13) 
     * @return EOK on success, otherwise -ve failure 
     */
    int (*if_send)(void *priv, const uint8_t *buf, size_t size);
    
    /**
     * @fn int (*if_recv)(void *priv, const uint8_t *buf, size_t 
     *     size
     * @brief Response receive from device 
     * 
     * @author rocke (2023-10-13)
     * 
     * @param priv   Interface handle
     * @param buf    Buffer to save the received 
     * @param size   Maximum number of bytes to receive 
     * 
     * @return Returns number of bytes received on success
     */
    int (*if_recv)(void *priv, const uint8_t *buf, size_t size);
    
    /**
     * @fn  int (*if_cleanup)(void *priv); 
     *  
     * @brief clean up whenever operation in complete 
     *  
     * @param priv  Interface handle 
     * 
     * @author rocke (2023-10-13)
     */
    int (*if_cleanup)(void *priv);
    
}athw_tpm_ops_t;

typedef struct _tpm_spi_handle_t {
    SPI_HandleTypeDef               *handle;
    athw_tpm_ops_t                  ops;
    athw_tpm_phy_ops_t              *phy_ops;
    void                            *dev;
    uint8_t                         iobuf[1024];
    uint8_t                         iostate; 
}__attribute__((packed)) tpm_spi_handle_t;

typedef struct _athw_dev_t {
    int     is_open;
    int     locality;
    int     vend_dev;
    u8      rid;
    uint32_t chip_type;
    uint32_t timeout_a;
    uint32_t timeout_b;
    uint32_t timeout_c;
    uint32_t timeout_d;
    athw_tpm_phy_ops_t *phy_ops;
    tpm_spi_handle_t *if_handle;
}__attribute__((packed)) athw_dev_t;


#define uswap_16(x) \
    ((((x) & 0xff00) >> 8) | \
     (((x) & 0x00ff) << 8))
     
#define uswap_32(x) \
    ((((x) & 0xff000000) >> 24) | \
     (((x) & 0x00ff0000) >>  8) | \
     (((x) & 0x0000ff00) <<  8) | \
     (((x) & 0x000000ff) << 24))

#define COMMAND_BUFFER_SIZE 256

/* Internal error of TPM command library */
#define TPM_LIB_ERROR ((u32)~0u)

/* To make strings of commands more easily */
#define __MSB(x) ((x) >> 8)
#define __LSB(x) ((x) & 0xFF)

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define cpu_to_le16(x)     (x)
# define cpu_to_le32(x)     (x)
# define cpu_to_le64(x)     (x)
# define le16_to_cpu(x)     (x)
# define le32_to_cpu(x)     (x)
# define le64_to_cpu(x)     (x)
# define cpu_to_be16(x)     uswap_16(x)
# define cpu_to_be32(x)     uswap_32(x)
# define cpu_to_be64(x)     uswap_64(x)
# define be16_to_cpu(x)     uswap_16(x)
# define be32_to_cpu(x)     uswap_32(x)
# define be64_to_cpu(x)     uswap_64(x)
#else
# define cpu_to_le16(x)     uswap_16(x)
# define cpu_to_le32(x)     uswap_32(x)
# define cpu_to_le64(x)     uswap_64(x)
# define le16_to_cpu(x)     uswap_16(x)
# define le32_to_cpu(x)     uswap_32(x)
# define le64_to_cpu(x)     uswap_64(x)
# define cpu_to_be16(x)     (x)
# define cpu_to_be32(x)     (x)
# define cpu_to_be64(x)     (x)
# define be16_to_cpu(x)     (x)
# define be32_to_cpu(x)     (x)
# define be64_to_cpu(x)     (x)
#endif

enum {
    TPM_MAX_ORDINAL         = 243,
    TPM_MAX_PROTECTED_ORDINAL   = 12,
    TPM_PROTECTED_ORDINAL_MASK  = 0xff,
    TPM_CMD_COUNT_BYTE      = 2,
    TPM_CMD_ORDINAL_BYTE        = 6,
};


enum {
    TPM_ACCESS_VALID        = 1 << 7,
    TPM_ACCESS_ACTIVE_LOCALITY  = 1 << 5,
    TPM_ACCESS_REQUEST_PENDING  = 1 << 2,
    TPM_ACCESS_REQUEST_USE      = 1 << 1,
    TPM_ACCESS_ESTABLISHMENT    = 1 << 0,
};

enum {
    TPM_STS_FAMILY_SHIFT        = 26,
    TPM_STS_FAMILY_MASK     = 0x3 << TPM_STS_FAMILY_SHIFT,
    TPM_STS_FAMILY_TPM2     = 1 << TPM_STS_FAMILY_SHIFT,
    TPM_STS_RESE_TESTABLISMENT_BIT  = 1 << 25,
    TPM_STS_COMMAND_CANCEL      = 1 << 24,
    TPM_STS_BURST_COUNT_SHIFT   = 8,
    TPM_STS_BURST_COUNT_MASK    = 0xffff << TPM_STS_BURST_COUNT_SHIFT,
    TPM_STS_VALID           = 1 << 7,
    TPM_STS_COMMAND_READY       = 1 << 6,
    TPM_STS_GO          = 1 << 5,
    TPM_STS_DATA_AVAIL      = 1 << 4,
    TPM_STS_DATA_EXPECT     = 1 << 3,
    TPM_STS_SELF_TEST_DONE      = 1 << 2,
    TPM_STS_RESPONSE_RETRY      = 1 << 1,
    TPM_STS_READ_ZERO               = 0x23
};


enum tpm_timeout {
    TPM_TIMEOUT_MS          = 5,
    TIS_SHORT_TIMEOUT_MS        = 750,
    TIS_LONG_TIMEOUT_MS     = 2000,
    SLEEP_DURATION_US       = 60,
    SLEEP_DURATION_LONG_US      = 210,
};


enum tis_int_flags {
    TPM_GLOBAL_INT_ENABLE = 0x80000000,
    TPM_INTF_BURST_COUNT_STATIC = 0x100,
    TPM_INTF_CMD_READY_INT = 0x080,
    TPM_INTF_INT_EDGE_FALLING = 0x040,
    TPM_INTF_INT_EDGE_RISING = 0x020,
    TPM_INTF_INT_LEVEL_LOW = 0x010,
    TPM_INTF_INT_LEVEL_HIGH = 0x008,
    TPM_INTF_LOCALITY_CHANGE_INT = 0x004,
    TPM_INTF_STS_VALID_INT = 0x002,
    TPM_INTF_DATA_AVAIL_INT = 0x001,
};


#define TPM_ACCESS(l)                   (0x0000 | ((l) << 12))
#define TPM_INT_ENABLE(l)               (0x0008 | ((l) << 12))
#define TPM_STS(l)                      (0x0018 | ((l) << 12))
#define TPM_DATA_FIFO(l)                (0x0024 | ((l) << 12))
#define TPM_DID_VID(l)                  (0x0f00 | ((l) << 12))
#define TPM_RID(l)                      (0x0f04 | ((l) << 12))
#define TPM_INTF_CAPS(l)                (0x0014 | ((l) << 12))

#define ATHW_TPM_TIMEOUT_RETRIES        1000000

#define __get_unaligned_t(type, ptr) ({                     \
    const struct { type x; } __packed * __pptr = (typeof(__pptr))(ptr); \
    __pptr->x;                              \
})

#define __put_unaligned_t(type, val, ptr) do {                  \
    struct { type x; } __packed * __pptr = (typeof(__pptr))(ptr);       \
    __pptr->x = (val);                          \
} while (0)

#define get_unaligned(ptr)  __get_unaligned_t(typeof(*(ptr)), (ptr))
#define put_unaligned(val, ptr) __put_unaligned_t(typeof(*(ptr)), (val), (ptr))


static inline u16 get_unaligned_le16(const void *p)
{
    return le16_to_cpu(__get_unaligned_t(__le16, p));
}

static inline u32 get_unaligned_le32(const void *p)
{
    return le32_to_cpu(__get_unaligned_t(__le32, p));
}



static inline void put_unaligned_le16(u16 val, void *p)
{
    __put_unaligned_t(__le16, cpu_to_le16(val), p);
}

static inline void put_unaligned_le32(u32 val, void *p)
{
    __put_unaligned_t(__le32, cpu_to_le32(val), p);
}



static inline u16 get_unaligned_be16(const void *p)
{
    return be16_to_cpu(__get_unaligned_t(__be16, p));
}

static inline u32 get_unaligned_be32(const void *p)
{
    return be32_to_cpu(__get_unaligned_t(__be32, p));
}



static inline void put_unaligned_be16(u16 val, void *p)
{
    __put_unaligned_t(__be16, cpu_to_be16(val), p);
}

static inline void put_unaligned_be32(u32 val, void *p)
{
    __put_unaligned_t(__be32, cpu_to_be32(val), p);
}



/* Allow unaligned memory access */
void athw_allow_unaligned(void);
bool athw_tpm_check_locality(void *dev, int loc);
int athw_tpm_request_locality(void *dev, int loc);
int athw_tpm_get_status(void *dev, u8 *status);
int athw_tpm_ready(void *dev);
int athw_tpm_wait_for_stat(void *dev, u8 mask, uint32_t timeout, u8 *status);
int athw_tpm_get_burstcount(void *dev, size_t *count);
int athw_tpm_dev_init(void *dev);
int athw_tpm_release_locality(void *dev, int loc);




#ifdef __cplusplus
}
#endif
#endif
