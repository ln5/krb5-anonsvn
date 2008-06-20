/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* #pragma ident	"@(#)ipropd_svc.c	1.2	04/02/20 SMI" */


#include <stdio.h>
#include <stdlib.h> /* getenv, exit */
#include <signal.h>
#include <sys/types.h>
#include <sys/resource.h> /* rlimit */
#include <syslog.h>

#include "k5-platform.h"
#include <kadm5/admin.h>
#include <kadm5/kadm_rpc.h>
#include <kadm5/server_internal.h>
#include <server_acl.h>
#include <adm_proto.h>
#include <string.h>
#include <gssapi_krb5.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <kdb_log.h>
#include "misc.h"
#include "osconf.h"

extern gss_name_t rqst2name(struct svc_req *rqstp);

extern int setup_gss_names(struct svc_req *, gss_buffer_desc *,
			   gss_buffer_desc *);
extern char *client_addr(struct svc_req *, char *);
extern void *global_server_handle;
extern int nofork;
extern short l_port;
static char abuf[33];

char *client_addr(struct svc_req *svc, char *buf) {
    return strcpy(buf, inet_ntoa(svc->rq_xprt->xp_raddr.sin_addr));
}

static char *reply_ok_str	= "UPDATE_OK";
static char *reply_err_str	= "UPDATE_ERROR";
static char *reply_fr_str	= "UPDATE_FULL_RESYNC_NEEDED";
static char *reply_busy_str	= "UPDATE_BUSY";
static char *reply_nil_str	= "UPDATE_NIL";
static char *reply_perm_str	= "UPDATE_PERM_DENIED";
static char *reply_unknown_str	= "<UNKNOWN_CODE>";

#define	LOG_UNAUTH  _("Unauthorized request: %s, %s, " \
			"client=%s, service=%s, addr=%s")
#define	LOG_DONE    _("Request: %s, %s, %s, client=%s, " \
			"service=%s, addr=%s")

#ifdef	DPRINT
#undef	DPRINT
#endif
#define	DPRINT(i) if (nofork) printf i


static void
debprret(char *w, update_status_t ret, kdb_sno_t sno)
{
	switch (ret) {
	case UPDATE_OK:
		printf("%s: end (OK, sno=%u)\n",
		    w, sno);
		break;
	case UPDATE_ERROR:
		printf("%s: end (ERROR)\n", w);
		break;
	case UPDATE_FULL_RESYNC_NEEDED:
		printf("%s: end (FR NEEDED)\n", w);
		break;
	case UPDATE_BUSY:
		printf("%s: end (BUSY)\n", w);
		break;
	case UPDATE_NIL:
		printf("%s: end (NIL)\n", w);
		break;
	case UPDATE_PERM_DENIED:
		printf("%s: end (PERM)\n", w);
		break;
	default:
		printf("%s: end (UNKNOWN return code (%d))\n", w, ret);
	}
}

static char *
replystr(update_status_t ret)
{
	switch (ret) {
	case UPDATE_OK:
		return (reply_ok_str);
	case UPDATE_ERROR:
		return (reply_err_str);
	case UPDATE_FULL_RESYNC_NEEDED:
		return (reply_fr_str);
	case UPDATE_BUSY:
		return (reply_busy_str);
	case UPDATE_NIL:
		return (reply_nil_str);
	case UPDATE_PERM_DENIED:
		return (reply_perm_str);
	default:
		return (reply_unknown_str);
	}
}

/* Returns null on allocation failure.
   Regardless of success or failure, frees the input buffer.  */
static char *
buf_to_string(gss_buffer_desc *b)
{
    OM_uint32 min_stat;
    char *s = malloc(b->length+1);

    if (s) {
	memcpy(s, b->value, b->length);
	s[b->length] = 0;
    }
    (void) gss_release_buffer(&min_stat, b);
    return s;
}

kdb_incr_result_t *
iprop_get_updates_1_svc(kdb_last_t *arg, struct svc_req *rqstp)
{
	static kdb_incr_result_t ret;
	char *whoami = "iprop_get_updates_1";
	int kret;
	kadm5_server_handle_t handle = global_server_handle;
	char *client_name = 0, *service_name = 0;
	char obuf[256] = {0};

	/* default return code */
	ret.ret = UPDATE_ERROR;

	DPRINT(("%s: start, last_sno=%lu\n", whoami,
		(unsigned long) arg->last_sno));

	if (!handle) {
		krb5_klog_syslog(LOG_ERR,
				_("%s: server handle is NULL"),
					whoami);
		goto out;
	}

	{
	    gss_buffer_desc client_desc, service_desc;

	    if (setup_gss_names(rqstp, &client_desc, &service_desc) < 0) {
		krb5_klog_syslog(LOG_ERR,
				 _("%s: setup_gss_names failed"),
				 whoami);
		goto out;
	    }
	    client_name = buf_to_string(&client_desc);
	    service_name = buf_to_string(&service_desc);
	    if (client_name == NULL || service_name == NULL) {
		free(client_name);
		free(service_name);
		krb5_klog_syslog(LOG_ERR,
				 "%s: out of memory recording principal names",
				 whoami);
		goto out;
	    }
	}

	DPRINT(("%s: clprinc=`%s'\n\tsvcprinc=`%s'\n",
		whoami, client_name, service_name));

	if (!kadm5int_acl_check(handle->context,
				rqst2name(rqstp),
				ACL_IPROP,
				NULL,
				NULL)) {
		ret.ret = UPDATE_PERM_DENIED;

		krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, whoami,
				"<null>", client_name, service_name,
				client_addr(rqstp, abuf));
		goto out;
	}

	kret = ulog_get_entries(handle->context, *arg, &ret);

	if (ret.ret == UPDATE_OK) {
		(void) snprintf(obuf, sizeof (obuf),
		_("%s; Incoming SerialNo=%lu; Outgoing SerialNo=%lu"),
				replystr(ret.ret),
				(unsigned long)arg->last_sno,
				(unsigned long)ret.lastentry.last_sno);
	} else {
		(void) snprintf(obuf, sizeof (obuf),
		_("%s; Incoming SerialNo=%lu; Outgoing SerialNo=N/A"),
				replystr(ret.ret),
				(unsigned long)arg->last_sno);
	}

	krb5_klog_syslog(LOG_NOTICE, LOG_DONE, whoami,
			obuf,
			((kret == 0) ? "success" : error_message(kret)),
			client_name, service_name,
			client_addr(rqstp, abuf));

out:
	if (nofork)
		debprret(whoami, ret.ret, ret.lastentry.last_sno);
	if (client_name)
		free(client_name);
	if (service_name)
		free(service_name);
	return (&ret);
}


/*
 * Given a client princ (foo/fqdn@R), copy (in arg cl) the fqdn substring.
 * Return arg cl str ptr on success, else NULL.
 */
static char *
getclhoststr(char *clprinc, char *cl, int len)
{
	char *s;
	if ((s = strchr(clprinc, '/')) != NULL) {
		/* XXX "!++s"?  */
		if (!++s)
		    return NULL;
		if (strlen(s) >= len)
		    return NULL;
		strcpy(cl, s);
		/* XXX Copy with @REALM first, with bounds check, then
		   chop off the realm??  */
		if ((s = strchr(cl, '@')) != NULL) {
			*s = '\0';
			return (cl); /* success */
		}
	}

	return (NULL);
}

kdb_fullresync_result_t *
iprop_full_resync_1_svc(
	/* LINTED */
	void *argp,
	struct svc_req *rqstp)
{
	static kdb_fullresync_result_t ret;
	char *tmpf = 0;
	char *ubuf = 0;
	char clhost[MAXHOSTNAMELEN] = {0};
	int pret, fret;
	kadm5_server_handle_t handle = global_server_handle;
	OM_uint32 min_stat;
	gss_name_t name = NULL;
	char *client_name = NULL, *service_name = NULL;
	char *whoami = "iprop_full_resync_1";

	/* default return code */
	ret.ret = UPDATE_ERROR;

	if (!handle) {
		krb5_klog_syslog(LOG_ERR,
				_("%s: server handle is NULL"),
					whoami);
		goto out;
	}

	DPRINT(("%s: start\n", whoami));

	{
	    gss_buffer_desc client_desc, service_desc;

	    if (setup_gss_names(rqstp, &client_desc, &service_desc) < 0) {
		krb5_klog_syslog(LOG_ERR,
				 _("%s: setup_gss_names failed"),
				 whoami);
		goto out;
	    }
	    client_name = buf_to_string(&client_desc);
	    service_name = buf_to_string(&service_desc);
	    if (client_name == NULL || service_name == NULL) {
		free(client_name);
		free(service_name);
		krb5_klog_syslog(LOG_ERR,
				 "%s: out of memory recording principal names",
				 whoami);
		goto out;
	    }
	}

	DPRINT(("%s: clprinc=`%s'\n\tsvcprinc=`%s'\n",
		whoami, client_name, service_name));

	if (!kadm5int_acl_check(handle->context,
				rqst2name(rqstp),
				ACL_IPROP,
				NULL,
				NULL)) {
		ret.ret = UPDATE_PERM_DENIED;

		krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, whoami,
				"<null>", client_name, service_name,
				client_addr(rqstp, abuf));
		goto out;
	}

	if (!getclhoststr(client_name, clhost, sizeof (clhost))) {
		krb5_klog_syslog(LOG_ERR,
			_("%s: getclhoststr failed"),
			whoami);
		goto out;
	}

	/*
	 * construct db dump file name; kprop style name + clnt fqdn
	 */
	if (asprintf(&tmpf, "%s_%s", KPROP_DEFAULT_FILE, clhost) < 0) {
	    krb5_klog_syslog(LOG_ERR,
			     _("%s: unable to construct db dump file name; out of memory"),
			     whoami);
		goto out;
	}

	/*
	 * note the -i; modified version of kdb5_util dump format
	 * to include sno (serial number)
	 */
	if (asprintf(&ubuf, "%s dump -i %s", KPROPD_DEFAULT_KDB5_UTIL,
		     tmpf) < 0) {
		krb5_klog_syslog(LOG_ERR,
				 _("%s: cannot construct kdb5 util dump string too long; out of memory"),
				 whoami);
		goto out;
	}

	/*
	 * Fork to dump the db and xfer it to the slave.
	 * (the fork allows parent to return quickly and the child
	 * acts like a callback to the slave).
	 */
	fret = fork();
	DPRINT(("%s: fork=%d (%d)\n", whoami, fret, getpid()));

	switch (fret) {
	case -1: /* error */
		if (nofork) {
			perror(whoami);
		}
		krb5_klog_syslog(LOG_ERR,
				_("%s: fork failed: %s"),
				whoami,
				error_message(errno));
		goto out;

	case 0: /* child */
		DPRINT(("%s: run `%s' ...\n", whoami, ubuf));
		(void) signal(SIGCHLD, SIG_DFL);
		/* run kdb5_util(1M) dump for IProp */
		pret = pclose(popen(ubuf, "w"));
		DPRINT(("%s: pclose=%d\n", whoami, pret));
		if (pret == -1) {
			if (nofork) {
				perror(whoami);
			}
			krb5_klog_syslog(LOG_ERR,
				_("%s: pclose(popen) failed: %s"),
					whoami,
					error_message(errno));
			goto out;
		}

		DPRINT(("%s: exec `kprop -f %s %s' ...\n",
			whoami, tmpf, clhost));
		/* XXX Yuck!  */
		if (getenv("KPROP_PORT"))
		    pret = execl(KPROPD_DEFAULT_KPROP, "kprop", "-f", tmpf,
				 "-P", getenv("KPROP_PORT"),
				 clhost, NULL);
		else
		    pret = execl(KPROPD_DEFAULT_KPROP, "kprop", "-f", tmpf,
				 clhost, NULL);
		if (pret == -1) {
			if (nofork) {
				perror(whoami);
			}
			krb5_klog_syslog(LOG_ERR,
					_("%s: exec failed: %s"),
					whoami,
					error_message(errno));
			goto out;
		}

	default: /* parent */
		ret.ret = UPDATE_OK;
		/* not used by slave (sno is retrieved from kdb5_util dump) */
		ret.lastentry.last_sno = 0;
		ret.lastentry.last_time.seconds = 0;
		ret.lastentry.last_time.useconds = 0;

		krb5_klog_syslog(LOG_NOTICE, LOG_DONE, whoami,
				"<null>",
				"success",
				client_name, service_name,
				client_addr(rqstp, abuf));

		goto out;
	}

out:
	if (nofork)
		debprret(whoami, ret.ret, 0);
	if (client_name)
		free(client_name);
	if (service_name)
		free(service_name);
	if (name)
		gss_release_name(&min_stat, &name);
	if (tmpf)
	    free(tmpf);
	if (ubuf)
	    free(ubuf);
	return (&ret);
}

void
krb5_iprop_prog_1(
	struct svc_req *rqstp,
	register SVCXPRT *transp)
{
	union {
		kdb_last_t iprop_get_updates_1_arg;
	} argument;
	char *result;
	bool_t (*_xdr_argument)(), (*_xdr_result)();
	char *(*local)(/* union XXX *, struct svc_req * */);
	char *whoami = "krb5_iprop_prog_1";

	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void) svc_sendreply(transp, xdr_void,
			(char *)NULL);
		return;

	case IPROP_GET_UPDATES:
		_xdr_argument = xdr_kdb_last_t;
		_xdr_result = xdr_kdb_incr_result_t;
		local = (char *(*)()) iprop_get_updates_1_svc;
		break;

	case IPROP_FULL_RESYNC:
		_xdr_argument = xdr_void;
		_xdr_result = xdr_kdb_fullresync_result_t;
		local = (char *(*)()) iprop_full_resync_1_svc;
		break;

	default:
		krb5_klog_syslog(LOG_ERR,
				_("RPC unknown request: %d (%s)"),
				rqstp->rq_proc, whoami);
		svcerr_noproc(transp);
		return;
	}
	(void) memset((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, _xdr_argument, (caddr_t)&argument)) {
		krb5_klog_syslog(LOG_ERR,
				_("RPC svc_getargs failed (%s)"),
				whoami);
		svcerr_decode(transp);
		return;
	}
	result = (*local)(&argument, rqstp);

	if (_xdr_result && result != NULL &&
	    !svc_sendreply(transp, _xdr_result, result)) {
		krb5_klog_syslog(LOG_ERR,
				_("RPC svc_sendreply failed (%s)"),
				whoami);
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, _xdr_argument, (caddr_t)&argument)) {
		krb5_klog_syslog(LOG_ERR,
				_("RPC svc_freeargs failed (%s)"),
				whoami);

		exit(1);
	}

	if (rqstp->rq_proc == IPROP_GET_UPDATES) {
		/* LINTED */
		kdb_incr_result_t *r = (kdb_incr_result_t *)result;

		if (r->ret == UPDATE_OK) {
			ulog_free_entries(r->updates.kdb_ulog_t_val,
					r->updates.kdb_ulog_t_len);
			r->updates.kdb_ulog_t_val = NULL;
			r->updates.kdb_ulog_t_len = 0;
		}
	}

}

#if 0
/*
 * Get the host base service name for the kiprop principal. Returns
 * KADM5_OK on success. Caller must free the storage allocated for
 * host_service_name.
 */
kadm5_ret_t
kiprop_get_adm_host_srv_name(
	krb5_context context,
	const char *realm,
	char **host_service_name)
{
	kadm5_ret_t ret;
	char *name;
	char *host;

	if (ret = kadm5_get_master(context, realm, &host))
		return (ret);

	name = malloc(strlen(KIPROP_SVC_NAME)+ strlen(host) + 2);
	if (name == NULL) {
		free(host);
		return (ENOMEM);
	}
	(void) sprintf(name, "%s@%s", KIPROP_SVC_NAME, host);
	free(host);
	*host_service_name = name;

	return (KADM5_OK);
}
#endif