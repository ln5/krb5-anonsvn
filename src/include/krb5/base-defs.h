/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Basic definitions for Kerberos V5 library
 */

#include <krb5/copyright.h>

#ifndef KRB5_BASE_DEFS__
#define KRB5_BASE_DEFS__

#include <krb5/wordsize.h>

#ifndef FALSE
#define	FALSE	0
#endif
#ifndef TRUE
#define	TRUE	1
#endif

typedef krb5_octet	krb5_boolean;
typedef krb5_int32	krb5_timestamp;
typedef krb5_ui_4	krb5_confounder;
typedef	krb5_octet	krb5_msgtype;
typedef	krb5_octet	krb5_kvno;
typedef	krb5_int32	krb5_flags;

typedef	krb5_ui_2	krb5_addrtype;
typedef krb5_ui_2	krb5_keytype;
typedef krb5_ui_2	krb5_enctype;
typedef krb5_ui_2	krb5_cksumtype;
typedef krb5_ui_2	krb5_authdatatype;

typedef	krb5_int32	krb5_error_code;
typedef krb5_int32	krb5_deltat;

typedef struct _krb5_data {
    int length;
    char *data;
} krb5_data;


#ifdef __STDC__
typedef	void * krb5_pointer;
typedef void const * krb5_const_pointer;
#define PROTOTYPE(x) x
#define DECLARG(type, val) type val
#define OLDDECLARG(type, val)
#else
/* make const & volatile available without effect */
#define const
#define volatile
typedef char * krb5_pointer;
typedef char * krb5_const_pointer;
#define PROTOTYPE(x) ()
#define DECLARG(type, val) val
#define OLDDECLARG(type, val) type val;
#endif /* __STDC__ */

typedef	krb5_data **	krb5_principal;	/* array of strings */
					/* CONVENTION: realm is first elem. */
/* constant version thereof: */
typedef krb5_data * const *  krb5_const_principal;

#define krb5_princ_realm(princ) ((princ)[0])

#endif /* KRB5_BASE_DEFS__ */
