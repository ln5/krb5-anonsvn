/*
 * winccld.c --- routine for dynamically loading the ccache DLL if
 * it's present.
 */

#include <windows.h>
#include <stdio.h>
#include "stdcc.h"

#define KRB5_WINCCLD_C_
#include "winccld.h"

static int krb5_win_ccdll_loaded = 0;

extern void krb5_win_ccdll_load();
extern int krb5_is_ccdll_loaded();

/*
 * return codes
 */
#define LF_OK		0
#define LF_NODLL	1
#define LF_NOFUNC	2

#define KRBCC_DLL      "krbcc32.dll"

static int LoadFuncs(const char* dll_name, FUNC_INFO fi[],
		     HINSTANCE* ph, int debug);

static int LoadFuncs(const char* dll_name, FUNC_INFO fi[],
		     HINSTANCE* ph, int debug)
{
    HINSTANCE h;
    int i, n;
    int error = 0;

    if (ph) *ph = 0;

    for (n = 0; fi[n].func_ptr_var; n++) {
	*(fi[n].func_ptr_var) = 0;
    }

    if (!(h = LoadLibrary(dll_name))) {
	return LF_NODLL;
    }

    if (debug)
	printf("Loaded %s\n", dll_name);
    for (i = 0; !error && (i < n); i++) {
	void* p = (void*)GetProcAddress(h, fi[i].func_name);
	if (!p) {
	    if (debug)
		printf("Could not get function: %s\n", fi[i].func_name);
	    error = 1;
	} else {
	    *(fi[i].func_ptr_var) = p;
	    if (debug)
		printf("Loaded function %s at 0x%08X\n", fi[i].func_name, p);
	}
    }
    if (error) {
	for (i = 0; i < n; i++) {
	    *(fi[i].func_ptr_var) = 0;
	}
	FreeLibrary(h);
	return LF_NOFUNC;
    }
    if (ph) *ph = h;
    return LF_OK;
}

void krb5_win_ccdll_load()
{
	if (krb5_win_ccdll_loaded)
		return;
	if (LoadFuncs(KRBCC_DLL, krbcc_fi, 0, 0))
		return;		/* Error, give up */
	krb5_win_ccdll_loaded = 1;
	krb5_cc_dfl_ops = &krb5_cc_stdcc_ops; /* Use stdcc! */
}

int krb5_is_ccdll_loaded()
{
	return krb5_win_ccdll_loaded;
}




