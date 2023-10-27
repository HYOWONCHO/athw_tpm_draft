/*
 * util_time.c
 *
 *  Created on: 2023. 10. 12.
 *      Author: rocke
 */

#include "util_time.h"
#include "stm32l4xx_hal.h"
#include "log.h"


void delay_ms(int ms)
{
    uint32_t tickstart = 0UL;
    uint32_t tickcur = 0UL;

    tickstart = HAL_GetTick();

    
    //tr_log("delay time : %d ms , start : %d", ms, tickstart);
    
    
    do {
        tickcur = HAL_GetTick();
    } while ((tickcur - tickstart) < ms);
    
    //tr_log("%d - %d = %d ms", tickcur, tickstart, tickcur - tickstart);
    
}


