/* @(#)clnt.h	2.1 88/07/29 4.0 RPCSRC; from 1.31 88/02/08 SMI*/
/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 * 
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 * 
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 * 
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 * 
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 * 
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */

/*
 * clnt.h - Client side remote procedure call interface.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

#ifndef _CLNT_
#define _CLNT_

/*
 * Rpc calls return an enum clnt_stat.  This should be looked at more,
 * since each implementation is required to live with this (implementation
 * independent) list of errors.
 */
enum clnt_stat {
	RPC_SUCCESS=0,			/* call succeeded */
	/*
	 * local errors
	 */
	RPC_CANTENCODEARGS=1,		/* can't encode arguments */
	RPC_CANTDECODERES=2,		/* can't decode results */
	RPC_CANTSEND=3,			/* failure in sending call */
	RPC_CANTRECV=4,			/* failure in receiving result */
	RPC_TIMEDOUT=5,			/* call timed out */
	/*
	 * remote errors
	 */
	RPC_VERSMISMATCH=6,		/* rpc versions not compatible */
	RPC_AUTHERROR=7,		/* authentication error */
	RPC_PROGUNAVAIL=8,		/* program not available */
	RPC_PROGVERSMISMATCH=9,		/* program version mismatched */
	RPC_PROCUNAVAIL=10,		/* procedure unavailable */
	RPC_CANTDECODEARGS=11,		/* decode arguments error */
	RPC_SYSTEMERROR=12,		/* generic "other problem" */

	/*
	 * callrpc & clnt_create errors
	 */
	RPC_UNKNOWNHOST=13,		/* unknown host name */
	RPC_UNKNOWNPROTO=17,		/* unkown protocol */

	/*
	 * _ create errors
	 */
	RPC_PMAPFAILURE=14,		/* the pmapper failed in its call */
	RPC_PROGNOTREGISTERED=15,	/* remote program is not registered */
	/*
	 * unspecified error
	 */
	RPC_FAILED=16
};


/*
 * Error info.
 */
struct rpc_err {
	enum clnt_stat re_status;
	union {
		int RE_errno;		/* realated system error */
		enum auth_stat RE_why;	/* why the auth error occurred */
		struct {
			rpc_u_int32 low;	/* lowest verion supported */
			rpc_u_int32 high;	/* highest verion supported */
		} RE_vers;
		struct {		/* maybe meaningful if RPC_FAILED */
			rpc_int32 s1;
			rpc_int32 s2;
		} RE_lb;		/* life boot & debugging only */
	} ru;
#define	re_errno	ru.RE_errno
#define	re_why		ru.RE_why
#define	re_vers		ru.RE_vers
#define	re_lb		ru.RE_lb
};


/*
 * Client rpc handle.
 * Created by individual implementations, see e.g. rpc_udp.c.
 * Client is responsible for initializing auth, see e.g. auth_none.c.
 */
typedef struct __rpc_client {
	AUTH	*cl_auth;			/* authenticator */
	struct clnt_ops {
	        /* call remote procedure */
	        enum clnt_stat	(*cl_call)(struct __rpc_client *,
					   rpc_u_int32, xdrproc_t, void *,
					   xdrproc_t, void *, 
					   struct timeval);	
                /* abort a call */
		void		(*cl_abort)(struct __rpc_client *);	
                /* get specific error code */
		void		(*cl_geterr)(struct __rpc_client *, 
					     struct rpc_err *);	
                /* frees results */
		bool_t		(*cl_freeres)(struct __rpc_client *,
					      xdrproc_t, void *);
                /* destroy this structure */
		void		(*cl_destroy)(struct __rpc_client *);
                /* the ioctl() of rpc */
		bool_t          (*cl_control)(struct __rpc_client *, int,
					      void *);
	} *cl_ops;
	caddr_t			cl_private;	/* private stuff */
} CLIENT;


/*
 * client side rpc interface ops
 *
 * Parameter types are:
 *
 */

/*
 * enum clnt_stat
 * CLNT_CALL(rh, proc, xargs, argsp, xres, resp, timeout)
 * 	CLIENT *rh;
 *	rpc_u_int32 proc;
 *	xdrproc_t xargs;
 *	caddr_t argsp;
 *	xdrproc_t xres;
 *	caddr_t resp;
 *	struct timeval timeout;
 */
#define	CLNT_CALL(rh, proc, xargs, argsp, xres, resp, secs)	\
	((*(rh)->cl_ops->cl_call)(rh, proc, xargs, argsp, xres, resp, secs))
#define	clnt_call(rh, proc, xargs, argsp, xres, resp, secs)	\
	((*(rh)->cl_ops->cl_call)(rh, proc, xargs, argsp, xres, resp, secs))

/*
 * void
 * CLNT_ABORT(rh);
 * 	CLIENT *rh;
 */
#define	CLNT_ABORT(rh)	((*(rh)->cl_ops->cl_abort)(rh))
#define	clnt_abort(rh)	((*(rh)->cl_ops->cl_abort)(rh))

/*
 * struct rpc_err
 * CLNT_GETERR(rh);
 * 	CLIENT *rh;
 */
#define	CLNT_GETERR(rh,errp)	((*(rh)->cl_ops->cl_geterr)(rh, errp))
#define	clnt_geterr(rh,errp)	((*(rh)->cl_ops->cl_geterr)(rh, errp))


/*
 * bool_t
 * CLNT_FREERES(rh, xres, resp);
 * 	CLIENT *rh;
 *	xdrproc_t xres;
 *	caddr_t resp;
 */
#define	CLNT_FREERES(rh,xres,resp) ((*(rh)->cl_ops->cl_freeres)(rh,xres,resp))
#define	clnt_freeres(rh,xres,resp) ((*(rh)->cl_ops->cl_freeres)(rh,xres,resp))

/*
 * bool_t
 * CLNT_CONTROL(cl, request, info)
 *      CLIENT *cl;
 *      unsigned int request;
 *      char *info;
 */
#define	CLNT_CONTROL(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
#define	clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))

/*
 * control operations that apply to both udp and tcp transports
 */
#define CLSET_TIMEOUT       1   /* set timeout (timeval) */
#define CLGET_TIMEOUT       2   /* get timeout (timeval) */
#define CLGET_SERVER_ADDR   3   /* get server's address (sockaddr) */
/*
 * udp only control operations
 */
#define CLSET_RETRY_TIMEOUT 4   /* set retry timeout (timeval) */
#define CLGET_RETRY_TIMEOUT 5   /* get retry timeout (timeval) */
/*
 * new control operations
 */
#define CLGET_LOCAL_ADDR    6	/* get local address (sockaddr, getsockname)*/

/*
 * void
 * CLNT_DESTROY(rh);
 * 	CLIENT *rh;
 */
#define	CLNT_DESTROY(rh)	((*(rh)->cl_ops->cl_destroy)(rh))
#define	clnt_destroy(rh)	((*(rh)->cl_ops->cl_destroy)(rh))


/*
 * RPCTEST is a test program which is accessable on every rpc
 * transport/port.  It is used for testing, performance evaluation,
 * and network administration.
 */

#define RPCTEST_PROGRAM		((rpc_u_int32)1)
#define RPCTEST_VERSION		((rpc_u_int32)1)
#define RPCTEST_NULL_PROC	((rpc_u_int32)2)
#define RPCTEST_NULL_BATCH_PROC	((rpc_u_int32)3)

/*
 * By convention, procedure 0 takes null arguments and returns them
 */

#define NULLPROC ((rpc_u_int32)0)

/*
 * Below are the client handle creation routines for the various
 * implementations of client side rpc.  They can return NULL if a 
 * creation failure occurs.
 */

/*
 * Memory based rpc (for speed check and testing)
 * CLIENT *
 * clntraw_create(prog, vers)
 *	rpc_u_int32 prog;
 *	rpc_u_int32 vers;
 */
#define clntraw_create	gssrpc_clntraw_create
extern CLIENT *clntraw_create(rpc_u_int32, rpc_u_int32);


/*
 * Generic client creation routine. Supported protocols are "udp" and "tcp"
 */
#define clnt_create	gssrpc_clnt_create
extern CLIENT *
clnt_create(char *, rpc_u_int32, rpc_u_int32, char *);



/*
 * TCP based rpc
 * CLIENT *
 * clnttcp_create(raddr, prog, vers, sockp, sendsz, recvsz)
 *	struct sockaddr_in *raddr;
 *	rpc_u_int32 prog;
 *	rpc_u_int32 version;
 *	register int *sockp;
 *	unsigned int sendsz;
 *	unsigned int recvsz;
 */
#define clnttcp_create	gssrpc_clnttcp_create
extern CLIENT *clnttcp_create(struct sockaddr_in *, rpc_u_int32, rpc_u_int32,
			      int *, unsigned int, unsigned int);

/*
 * UDP based rpc.
 * CLIENT *
 * clntudp_create(raddr, program, version, wait, sockp)
 *	struct sockaddr_in *raddr;
 *	rpc_u_int32 program;
 *	rpc_u_int32 version;
 *	struct timeval wait;
 *	int *sockp;
 *
 * Same as above, but you specify max packet sizes.
 * CLIENT *
 * clntudp_bufcreate(raddr, program, version, wait, sockp, sendsz, recvsz)
 *	struct sockaddr_in *raddr;
 *	rpc_u_int32 program;
 *	rpc_u_int32 version;
 *	struct timeval wait;
 *	int *sockp;
 *	unsigned int sendsz;
 *	unsigned int recvsz;
 */
#define clntudp_create		gssrpc_clntudp_create
#define clntudp_bufcreate	gssrpc_clntudp_bufcreate
extern CLIENT *clntudp_create(struct sockaddr_in *, rpc_u_int32, 
			      rpc_u_int32, struct timeval, int *);
extern CLIENT *clntudp_bufcreate(struct sockaddr_in *, rpc_u_int32, 
				 rpc_u_int32, struct timeval, int *,
				 unsigned int, unsigned int);

#define _rpc_dtablesize _gssrpc_rpc_dtablesize
extern int _rpc_dtablesize(void);
/*
 * Print why creation failed
 */
#define clnt_pcreateerror	gssrpc_clnt_pcreateerror
#define clnt_spcreateerror	gssrpc_clnt_spcreateerror
void clnt_pcreateerror(char *);	/* stderr */
char *clnt_spcreateerror(char *);	/* string */

/*
 * Like clnt_perror(), but is more verbose in its output
 */ 
#define clnt_perrno		gssrpc_clnt_perrno
void clnt_perrno(enum clnt_stat num);	/* stderr */

/*
 * Print an English error message, given the client error code
 */
#define clnt_perror		gssrpc_clnt_perror
#define clnt_sperror		gssrpc_clnt_sperror
void clnt_perror(CLIENT *, char *); 	/* stderr */
char *clnt_sperror(CLIENT *, char *);	/* string */

/* 
 * If a creation fails, the following allows the user to figure out why.
 */
#define rpc_createerr gssrpc_rpc_createrr
struct rpc_createerr {
	enum clnt_stat cf_stat;
	struct rpc_err cf_error; /* useful when cf_stat == RPC_PMAPFAILURE */
};

extern struct rpc_createerr rpc_createerr;



/*
 * Copy error message to buffer.
 */
#define clnt_sperrno		gssrpc_clnt_sperrno
char *clnt_sperrno(enum clnt_stat num);	/* string */

#define UDPMSGSIZE	8800	/* rpc imposed limit on udp msg size */
#define RPCSMALLMSGSIZE	400	/* a more reasonable packet size */

#endif /*!_CLNT_*/
