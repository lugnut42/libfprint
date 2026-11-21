/*
 * ChromeOS Fingerprint driver for libfprint - machine key storage
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include <gio/gio.h>

G_BEGIN_DECLS

/* The FPMCU derives the template encryption key from the seed, the user
 * context and a secret that never leaves the MCU. ChromeOS keeps the seed
 * in the TPM; this driver generates both values once per machine and keeps
 * them in fprintd's state directory (StateDirectory=fprint, mode 0700).
 *
 * The leading dot keeps the directory name out of the user name space:
 * fprintd stores prints as <state dir>/<user name>/..., and user names
 * cannot start with a dot.
 */
#define CRFPMOC_KEYS_FILE "/var/lib/fprint/.crfpmoc/key"

#define CRFPMOC_KEYS_SEED_BYTES 32
#define CRFPMOC_KEYS_CONTEXT_BYTES 32

/* File format: magic (8 bytes), version (guint32 little endian), seed,
 * context. Nothing else, so the size is exact. */
#define CRFPMOC_KEYS_MAGIC "CRFPMKEY"
#define CRFPMOC_KEYS_VERSION 1

gboolean crfpmoc_keys_load_or_create (const char *path,
                                      gboolean    may_create,
                                      guint8      seed[CRFPMOC_KEYS_SEED_BYTES],
                                      guint8      context[CRFPMOC_KEYS_CONTEXT_BYTES],
                                      gboolean   *created,
                                      GError    **error);

gboolean crfpmoc_keys_seed_action (gboolean  key_is_new,
                                   gboolean  seed_needed,
                                   gboolean *send_seed,
                                   GError  **error);

G_END_DECLS
