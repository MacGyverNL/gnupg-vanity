/* compress.c - compress filter
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#ifdef HAVE_ZLIB_H
  #include <zlib.h>
#endif

#include "util.h"
#include "memory.h"
#include "packet.h"
#include "filter.h"
#include "options.h"


#ifdef HAVE_ZLIB_H
static void
init_compress( compress_filter_context_t *zfx, z_stream *zs )
{
    int rc;
    byte *inbuf, *outbuf;
    int level;


    if( opt.compress >= 0 && opt.compress <= 9 )
	level = opt.compress;
    else if( opt.compress == -1 )
	level = Z_DEFAULT_COMPRESSION;
    else if( opt.compress == 10 ) /* remove this ! */
	level = 0;
    else {
	log_error("invalid compression level; using default level\n");
	level = Z_DEFAULT_COMPRESSION;
    }

    if( (rc = deflateInit( zs, level )) != Z_OK ) {
	log_fatal("zlib problem: %s\n", zs->msg? zs->msg :
			       rc == Z_MEM_ERROR ? "out of core" :
			       rc == Z_VERSION_ERROR ? "invalid lib version" :
						       "unknown error" );
    }

    zfx->outbufsize = 4096;
    zfx->outbuf = m_alloc( zfx->outbufsize );
}

static int
do_compress( compress_filter_context_t *zfx, z_stream *zs, int flush, IOBUF a )
{
    int zrc;
    unsigned n;

    do {
	zs->next_out = zfx->outbuf;
	zs->avail_out = zfx->outbufsize;
	zrc = deflate( zs, flush );
	if( zrc == Z_STREAM_END && flush == Z_FINISH )
	    ;
	else if( zrc != Z_OK ) {
	    if( zs->msg )
		log_fatal("zlib deflate problem: %s\n", zs->msg );
	    else
		log_fatal("zlib deflate problem: rc=%d\n", zrc );
	}
	n = zfx->outbufsize - zs->avail_out;
	if( DBG_FILTER )
	    log_debug("deflate returned: avail_in=%u, avail_out=%u, n=%u\n",
		(unsigned)zs->avail_in, (unsigned)zs->avail_out, (unsigned)n );

	if( iobuf_write( a, zfx->outbuf, n ) ) {
	    log_debug("deflate: iobuf_write failed\n");
	    return G10ERR_WRITE_FILE;
	}
    } while( zs->avail_in || (flush == Z_FINISH && zrc != Z_STREAM_END) );
    return 0;
}

static void
init_uncompress( compress_filter_context_t *zfx, z_stream *zs )
{
    int rc;
    byte *inbuf, *outbuf;
    int level;


    if( (rc = inflateInit( zs )) != Z_OK ) {
	log_fatal("zlib problem: %s\n", zs->msg? zs->msg :
			       rc == Z_MEM_ERROR ? "out of core" :
			       rc == Z_VERSION_ERROR ? "invalid lib version" :
						       "unknown error" );
    }

    zfx->inbufsize = 1024;
    zfx->inbuf = m_alloc( zfx->inbufsize );
    zs->avail_in = 0;
}

static int
do_uncompress( compress_filter_context_t *zfx, z_stream *zs,
	       IOBUF a, size_t *ret_len )
{
    int zrc;
    int rc=0;
    size_t n;
    byte *p;
    int c;

    if( DBG_FILTER )
	log_debug("do_uncompress: avail_in=%u, avail_out=%u\n",
		(unsigned)zs->avail_in, (unsigned)zs->avail_out);
    do {
	if( zs->avail_in < zfx->inbufsize ) {
	    n = zs->avail_in;
	    if( !n )
		zs->next_in = zfx->inbuf;
	    for( p=zfx->inbuf+n; n < zfx->inbufsize; n++, p++ ) {
		if( (c=iobuf_get(a)) == -1 )
		    break;
		*p = c & 0xff;
	    }
	    zs->avail_in = n;
	}
	zrc = inflate( zs, Z_PARTIAL_FLUSH );
	if( DBG_FILTER )
	    log_debug("inflate returned: avail_in=%u, avail_out=%u, zrc=%d\n",
		   (unsigned)zs->avail_in, (unsigned)zs->avail_out, zrc);
	if( zrc == Z_STREAM_END )
	    rc = -1; /* eof */
	else if( zrc != Z_OK ) {
	    if( zs->msg )
		log_fatal("zlib inflate problem: %s\n", zs->msg );
	    else
		log_fatal("zlib inflate problem: rc=%d\n", zrc );
	}
    } while( zs->avail_out && zrc != Z_STREAM_END );
    *ret_len = zfx->outbufsize - zs->avail_out;
    if( DBG_FILTER )
	log_debug("do_uncompress: returning %u bytes\n", (unsigned)*ret_len );
    return rc;
}

int
compress_filter( void *opaque, int control,
		 IOBUF a, byte *buf, size_t *ret_len)
{
    size_t size = *ret_len;
    compress_filter_context_t *zfx = opaque;
    z_stream *zs = zfx->opaque;
    int zrc, rc=0;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	if( !zfx->status ) {
	    zs = zfx->opaque = m_alloc_clear( sizeof *zs );
	    init_uncompress( zfx, zs );
	    zfx->status = 1;
	}

	zs->next_out = buf;
	zs->avail_out = size;
	zfx->outbufsize = size; /* needed only for calculation */
	rc = do_uncompress( zfx, zs, a, ret_len );
    }
    else if( control == IOBUFCTRL_FLUSH ) {
	if( !zfx->status ) {
	    PACKET pkt;
	    PKT_compressed cd;

	    memset( &cd, 0, sizeof cd );
	    cd.len = 0;
	    cd.algorithm = 2; /* zlib */
	    init_packet( &pkt );
	    pkt.pkttype = PKT_COMPRESSED;
	    pkt.pkt.compressed = &cd;
	    if( build_packet( a, &pkt ))
		log_bug("build_packet(PKT_COMPRESSED) failed\n");
	    zs = zfx->opaque = m_alloc_clear( sizeof *zs );
	    init_compress( zfx, zs );
	    zfx->status = 2;
	}

	zs->next_in = buf;
	zs->avail_in = size;
	rc = do_compress( zfx, zs, Z_NO_FLUSH, a );
    }
    else if( control == IOBUFCTRL_FREE ) {
	if( zfx->status == 1 ) {
	    inflateEnd(zs);
	    m_free(zs);
	    zfx->opaque = NULL;
	    m_free(zfx->outbuf); zfx->outbuf = NULL;
	}
	else if( zfx->status == 2 ) {
	    zs->next_in = buf;
	    zs->avail_in = 0;
	    do_compress( zfx, zs, Z_FINISH, a );
	    deflateEnd(zs);
	    m_free(zs);
	    zfx->opaque = NULL;
	    m_free(zfx->outbuf); zfx->outbuf = NULL;
	}
    }
    else if( control == IOBUFCTRL_DESC )
	*(char**)buf = "compress_filter";
    return rc;
}
#else /* No ZLIB */
int
compress_filter( void *opaque, int control,
		 IOBUF a, byte *buf, size_t *ret_len)
{
    size_t size = *ret_len;
    compress_filter_context_t *zfx = opaque;
    int c, rc=0;
    size_t n;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	for( n=0; n < size; n++ ) {
	    if( (c=iobuf_get(a)) == -1 )
		break;
	    buf[n] = c & 0xff;
	}
	if( !n )
	    rc = -1;
	*ret_len = n;
    }
    else if( control == IOBUFCTRL_FLUSH ) {
	if( iobuf_write( a, buf, size ) )
	    rc = G10ERR_WRITE_FILE;
    }
    else if( control == IOBUFCTRL_DESC )
	*(char**)buf = "dummy compress_filter";
    return rc;
}
#endif /*no ZLIB*/

/****************
 * Handle a compressed packet
 */
int
handle_compressed( PKT_compressed *cd )
{
    compress_filter_context_t cfx;

    memset( &cfx, 0, sizeof cfx );
    if( cd->algorithm != 2 )
	return G10ERR_COMPR_ALGO;

    iobuf_push_filter( cd->buf, compress_filter, &cfx );
    proc_packets(cd->buf);
    iobuf_pop_filter( cd->buf, compress_filter, &cfx );
  #if 0
    if( cd->len )
	iobuf_set_limit( cd->buf, 0 ); /* disable the readlimit */
    else
	iobuf_clear_eof( cd->buf );
  #endif
    cd->buf = NULL;
    return 0;
}

