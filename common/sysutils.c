/* sysutils.c -  system helpers
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#ifdef WITHOUT_GNU_PTH /* Give the Makefile a chance to build without Pth.  */
# undef HAVE_PTH
# undef USE_GNU_PTH
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_STAT
# include <sys/stat.h>
#endif
#if defined(__linux__) && defined(__alpha__) && __GLIBC__ < 2
# include <asm/sysinfo.h>
# include <asm/unistd.h>
#endif
#ifdef HAVE_SETRLIMIT
# include <time.h>
# include <sys/time.h>
# include <sys/resource.h>
#endif
#ifdef HAVE_W32_SYSTEM
# include <windows.h>
#endif
#ifdef HAVE_PTH      
# include <pth.h>
#endif

#include "util.h"
#include "i18n.h"

#include "sysutils.h"

#if defined(__linux__) && defined(__alpha__) && __GLIBC__ < 2
#warning using trap_unaligned
static int
setsysinfo(unsigned long op, void *buffer, unsigned long size,
		     int *start, void *arg, unsigned long flag)
{
    return syscall(__NR_osf_setsysinfo, op, buffer, size, start, arg, flag);
}

void
trap_unaligned(void)
{
    unsigned int buf[2];

    buf[0] = SSIN_UACPROC;
    buf[1] = UAC_SIGBUS | UAC_NOPRINT;
    setsysinfo(SSI_NVPAIRS, buf, 1, 0, 0, 0);
}
#else
void
trap_unaligned(void)
{  /* dummy */
}
#endif


int
disable_core_dumps (void)
{
#ifdef HAVE_DOSISH_SYSTEM
    return 0;
#else
# ifdef HAVE_SETRLIMIT
    struct rlimit limit;

    /* We only set the current limit unless we were not able to
       retrieve the old value. */
    if (getrlimit (RLIMIT_CORE, &limit))
      limit.rlim_max = 0;
    limit.rlim_cur = 0;
    if( !setrlimit (RLIMIT_CORE, &limit) )
	return 0;
    if( errno != EINVAL && errno != ENOSYS )
	log_fatal (_("can't disable core dumps: %s\n"), strerror(errno) );
#endif
    return 1;
#endif
}

int
enable_core_dumps (void)
{
#ifdef HAVE_DOSISH_SYSTEM
    return 0;
#else
# ifdef HAVE_SETRLIMIT
    struct rlimit limit;

    if (getrlimit (RLIMIT_CORE, &limit))
      return 1;
    limit.rlim_cur = limit.rlim_max;
    setrlimit (RLIMIT_CORE, &limit);
    return 1; /* We always return true because trhis function is
                 merely a debugging aid. */
# endif
    return 1;
#endif
}



/* Return a string which is used as a kind of process ID */
const byte *
get_session_marker( size_t *rlen )
{
    static byte marker[SIZEOF_UNSIGNED_LONG*2];
    static int initialized;

    if ( !initialized ) {
        volatile ulong aa, bb; /* we really want the uninitialized value */
        ulong a, b;

        initialized = 1;
        /* Although this marker is guessable it is not easy to use
         * for a faked control packet because an attacker does not
         * have enough control about the time the verification does 
         * take place.  Of course, we can add just more random but 
         * than we need the random generator even for verification
         * tasks - which does not make sense. */
        a = aa ^ (ulong)getpid();
        b = bb ^ (ulong)time(NULL);
        memcpy( marker, &a, SIZEOF_UNSIGNED_LONG );
        memcpy( marker+SIZEOF_UNSIGNED_LONG, &b, SIZEOF_UNSIGNED_LONG );
    }
    *rlen = sizeof(marker);
    return marker;
}


#if 0 /* not yet needed - Note that this will require inclusion of
         cmacros.am in Makefile.am */
int
check_permissions(const char *path,int extension,int checkonly)
{
#if defined(HAVE_STAT) && !defined(HAVE_DOSISH_SYSTEM)
  char *tmppath;
  struct stat statbuf;
  int ret=1;
  int isdir=0;

  if(opt.no_perm_warn)
    return 0;

  if(extension && path[0]!=DIRSEP_C)
    {
      if(strchr(path,DIRSEP_C))
	tmppath=make_filename(path,NULL);
      else
	tmppath=make_filename(GNUPG_LIBDIR,path,NULL);
    }
  else
    tmppath=m_strdup(path);

  /* It's okay if the file doesn't exist */
  if(stat(tmppath,&statbuf)!=0)
    {
      ret=0;
      goto end;
    }

  isdir=S_ISDIR(statbuf.st_mode);

  /* Per-user files must be owned by the user.  Extensions must be
     owned by the user or root. */
  if((!extension && statbuf.st_uid != getuid()) ||
     (extension && statbuf.st_uid!=0 && statbuf.st_uid!=getuid()))
    {
      if(!checkonly)
	log_info(_("Warning: unsafe ownership on %s \"%s\"\n"),
		 isdir?"directory":extension?"extension":"file",path);
      goto end;
    }

  /* This works for both directories and files - basically, we don't
     care what the owner permissions are, so long as the group and
     other permissions are 0 for per-user files, and non-writable for
     extensions. */
  if((extension && (statbuf.st_mode & (S_IWGRP|S_IWOTH)) !=0) ||
     (!extension && (statbuf.st_mode & (S_IRWXG|S_IRWXO)) != 0))
    {
      char *dir;

      /* However, if the directory the directory/file is in is owned
         by the user and is 700, then this is not a problem.
         Theoretically, we could walk this test up to the root
         directory /, but for the sake of sanity, I'm stopping at one
         level down. */

      dir= make_dirname (tmppath);
      if(stat(dir,&statbuf)==0 && statbuf.st_uid==getuid() &&
	 S_ISDIR(statbuf.st_mode) && (statbuf.st_mode & (S_IRWXG|S_IRWXO))==0)
	{
	  xfree (dir);
	  ret=0;
	  goto end;
	}

      m_free(dir);

      if(!checkonly)
	log_info(_("Warning: unsafe permissions on %s \"%s\"\n"),
		 isdir?"directory":extension?"extension":"file",path);
      goto end;
    }

  ret=0;

 end:
  m_free(tmppath);

  return ret;

#endif /* HAVE_STAT && !HAVE_DOSISH_SYSTEM */

  return 0;
}
#endif


/* Wrapper around the usual sleep fucntion.  This one won't wake up
   before the sleep time has really elapsed.  When build with Pth it
   merely calls pth_sleep and thus suspends only the current
   thread. */
void
gnupg_sleep (unsigned int seconds)
{
#ifdef HAVE_PTH
  /* With Pth we force a regular sleep for seconds == 0 so that also
     the process will give up its timeslot.  */
  if (!seconds)
    {
# ifdef HAVE_W32_SYSTEM    
      Sleep (0);
# else
      sleep (0);
# endif
    }
  pth_sleep (seconds);
#else
  /* Fixme:  make sure that a sleep won't wake up to early.  */
# ifdef HAVE_W32_SYSTEM    
  Sleep (seconds*1000);
# else
  sleep (seconds);
# endif
#endif
}


/* This function is a NOP for POSIX systems but required under Windows
   as the file handles as returned by OS calls (like CreateFile) are
   different from the libc file descriptors (like open). This function
   translates system file handles to libc file handles.  FOR_WRITE
   gives the direction of the handle.  */
int
translate_sys2libc_fd (gnupg_fd_t fd, int for_write)
{
#ifdef HAVE_W32_SYSTEM
  int x;

  if (fd == GNUPG_INVALID_FD)
    return -1;
  
  /* Note that _open_osfhandle is currently defined to take and return
     a long.  */
  x = _open_osfhandle ((long)fd, for_write ? 1 : 0);
  if (x == -1)
    log_error ("failed to translate osfhandle %p\n", (void *) fd);
  return x;
#else /*!HAVE_W32_SYSTEM */
  return fd;
#endif
}

/* This is the same as translate_sys2libc_fd but takes an integer
   which is assumet to be such an system handle.  */
int
translate_sys2libc_fd_int (int fd, int for_write)
{
#ifdef HAVE_W32_SYSTEM
  if (fd <= 2)
    return fd;	/* Do not do this for error, stdin, stdout, stderr. */

  return translate_sys2libc_fd ((void*)fd, for_write);
#else
  return fd;
#endif
}