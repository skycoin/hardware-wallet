
#ifndef __DROPLET_H__
#define __DROPLET_H__

#include <stdint.h>
#include <string.h>

/**
 * String representation of coins
 */
char *sprint_coins(uint64_t coins, uint32_t precision_exp, size_t sz, char *msg);

#endif
