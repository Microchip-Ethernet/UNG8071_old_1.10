/**
 * This file contains shared configurations between the network and switch
 * drivers.
 */


#ifndef KSZ_CFG_8795_H
#define KSZ_CFG_8795_H


#include "ksz_common.h"

#if defined(CONFIG_KSZ_DLR)
#define USE_REQ
#endif

#ifdef USE_REQ
#include "ksz_req.h"
#endif

#include "ksz8795.h"
#include "ksz_sw_8795.h"

#endif

