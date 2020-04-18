#ifndef _NGX_LIVE_DVR_H_INCLUDED_
#define _NGX_LIVE_DVR_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"
#include "ngx_live_store.h"

char *ngx_live_dvr_set_store(ngx_conf_t *cf, ngx_live_store_t *store);

#endif /* _NGX_LIVE_DVR_H_INCLUDED_ */
