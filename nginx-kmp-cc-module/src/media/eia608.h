/*****************************************************************************
 * eia608.h
 *****************************************************************************
 * Copyright (C) 2007 Laurent Aimar
 *
 * Authors: Laurent Aimar <fenrir@via.ecp.fr>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#ifndef VLC_EIA608_H_
#define VLC_EIA608_H_


#include "decoder.h"


typedef struct eia608_t eia608_t;


eia608_t *Eia608New(cc_log_t *, uint32_t, void *, subtitle_handler_t *);
void Eia608Release(eia608_t *h);

void Eia608Parse(void *ctx, vlc_tick_t tick, uint8_t *p_data, size_t i_data);

#endif
