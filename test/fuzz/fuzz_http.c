/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: J. Neuschäfer <j.ne@posteo.net>
 */

#include "lwip/sys.h"
#include "lwip/init.h"
#include "lwip/altcp.h"
#include "lwip/priv/altcp_priv.h"
#include "lwip/apps/httpd.h"

#include <stdio.h>
#include <string.h>

static err_t
altcp_fuzz_connect(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port, altcp_connected_fn connected)
{
  LWIP_UNUSED_ARG(ipaddr);
  LWIP_UNUSED_ARG(port);

  if (conn == NULL) {
    return ERR_VAL;
  }
  conn->connected = connected;
  return ERR_OK;
}

static struct altcp_pcb *
altcp_fuzz_listen(struct altcp_pcb *conn, u8_t backlog, err_t *err)
{
  LWIP_UNUSED_ARG(conn);
  LWIP_UNUSED_ARG(backlog);
  LWIP_UNUSED_ARG(err);

  return conn;
}

static err_t
altcp_fuzz_close(struct altcp_pcb *conn)
{
  LWIP_UNUSED_ARG(conn);

  return ERR_OK;
}

static void
altcp_fuzz_abort(struct altcp_pcb *conn)
{
  LWIP_UNUSED_ARG(conn);
}

static err_t
altcp_fuzz_bind(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port)
{
  LWIP_UNUSED_ARG(conn);
  LWIP_UNUSED_ARG(ipaddr);
  LWIP_UNUSED_ARG(port);

  return ERR_OK;
}

static err_t
altcp_fuzz_write(struct altcp_pcb *conn, const void *dataptr, u16_t len, u8_t apiflags)
{
  LWIP_UNUSED_ARG(conn);
  LWIP_UNUSED_ARG(apiflags);

  printf("\033[1;33m");
  fwrite(dataptr, 1, len, stdout);
  printf("\033[m");

  return ERR_OK;
}

static u16_t
altcp_fuzz_mss(struct altcp_pcb *conn)
{
  LWIP_UNUSED_ARG(conn);
  return 0x7fff;
}

static u16_t
altcp_fuzz_sndbuf(struct altcp_pcb *conn)
{
  LWIP_UNUSED_ARG(conn);
  return 0xffff;
}

const struct altcp_functions altcp_fuzz_functions = {
  altcp_default_set_poll,
  altcp_default_recved,
  altcp_fuzz_bind,
  altcp_fuzz_connect,
  altcp_fuzz_listen,
  altcp_fuzz_abort,
  altcp_fuzz_close,
  altcp_default_shutdown,
  altcp_fuzz_write,
  altcp_default_output,
  altcp_fuzz_mss,
  altcp_fuzz_sndbuf,
  altcp_default_sndqueuelen,
  altcp_default_nagle_disable,
  altcp_default_nagle_enable,
  altcp_default_nagle_disabled,
  altcp_default_setprio,
  altcp_default_dealloc,
  altcp_default_get_tcp_addrinfo,
  altcp_default_get_ip,
  altcp_default_get_port,
#if LWIP_TCP_KEEPALIVE
  altcp_default_keepalive_disable,
  altcp_default_keepalive_enable,
#endif
#ifdef LWIP_DEBUG
  altcp_default_dbg_get_tcp_state,
#endif
};

static struct altcp_pcb *altcp_fuzz_alloc()
{
  struct altcp_pcb *conn = altcp_alloc();
  if (conn)
    conn->fns = &altcp_fuzz_functions;
  return conn;
}

static struct altcp_pcb *http_conn;

static void init_all()
{
  lwip_init();

  http_conn = altcp_fuzz_alloc();
  httpd_init_pcb(http_conn, 80);
}

static void test_input(void *input, size_t len)
{
  struct altcp_pcb *conn = http_conn;
  struct pbuf *p, *q;
  u8_t *data = input;
  err_t err;

  conn->accept(conn->arg, conn, ERR_OK);

  p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
  LWIP_ASSERT("alloc failed", p);
  for(q = p; q != NULL; q = q->next) {
    MEMCPY(q->payload, data, q->len);
    data += q->len;
  }

  err = conn->recv(conn->arg, conn, p, ERR_OK);
  if (err != ERR_OK) {
    pbuf_free(p);
  }
}

#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT()

int main(int argc, char** argv)
{
  LWIP_UNUSED_ARG(argc);
  LWIP_UNUSED_ARG(argv);

  init_all();

  __AFL_INIT();

  while (__AFL_LOOP(100)) {
    test_input(__AFL_FUZZ_TESTCASE_BUF, __AFL_FUZZ_TESTCASE_LEN);
  }
}
#else
int main(int argc, char** argv)
{
  static char pktbuf[10000];
  size_t len;

  init_all();

  if(argc > 1) {
    FILE* f;
    const char* filename;
    printf("reading input from file... ");
    fflush(stdout);
    filename = argv[1];
    LWIP_ASSERT("invalid filename", filename != NULL);
    f = fopen(filename, "rb");
    LWIP_ASSERT("open failed", f != NULL);
    len = fread(pktbuf, 1, sizeof(pktbuf), f);
    fclose(f);
    printf("testing file: \"%s\"...\r\n", filename);
  } else {
    len = fread(pktbuf, 1, sizeof(pktbuf), stdin);
  }

  test_input(pktbuf, len);

  return 0;
}
#endif
