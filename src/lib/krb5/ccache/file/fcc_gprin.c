/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_fcc_get_principal.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_gprinc_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>
#include "fcc.h"

/*
 * Modifies:
 * id, princ
 *
 * Effects:
 * Retrieves the primary principal from id, as set with
 * krb5_fcc_initialize.  The principal is returned is allocated
 * storage that must be freed by the caller via krb5_free_principal.
 *
 * Errors:
 * system errors
 * KRB5_CC_NOMEM
 */
krb5_error_code
krb5_fcc_get_principal(id, princ)
   krb5_ccache id;
   krb5_principal *princ;
{
     krb5_error_code kret;

     if (OPENCLOSE(id)) {
	  kret = open(((krb5_fcc_data *) id->data)->filename, O_RDONLY, 0);
	  if (kret < 0)
	       return errno;
	  ((krb5_fcc_data *) id->data)->fd = kret;
     }
     else
	  lseek(((krb5_fcc_data *) id->data)->fd, 0, L_SET);

     kret = krb5_fcc_read_principal(id, princ);

     if (OPENCLOSE(id)) {
	  close(((krb5_fcc_data *) id->data)->fd);
	  ((krb5_fcc_data *) id->data)->fd = -1;
     }
     return kret;
}

     
