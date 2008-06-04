/*
 * $Header$
 *
 * Copyright 2006 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#ifndef KIM_CCACHE_PRIVATE_H
#define KIM_CCACHE_PRIVATE_H

#include <kim/kim.h>

kim_error_t kim_ccache_create_from_display_name (kim_ccache_t  *out_ccache,
                                                 kim_string_t   in_display_name);

kim_error_t kim_ccache_compare (kim_ccache_t   in_ccache,
                                kim_ccache_t   in_compare_to_ccache,
                                kim_boolean_t *out_equal);

#endif /* KIM_CCACHE_PRIVATE_H */