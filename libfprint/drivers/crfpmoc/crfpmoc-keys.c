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

/* This file only depends on GLib and libc so that it can be tested on its
 * own. It never logs key bytes. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* renameat2, explicit_bzero */
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crfpmoc-keys.h"

#define MAGIC_BYTES (sizeof (CRFPMOC_KEYS_MAGIC) - 1)
#define HEADER_BYTES (MAGIC_BYTES + 4)
#define SEED_OFFSET HEADER_BYTES
#define CONTEXT_OFFSET (SEED_OFFSET + CRFPMOC_KEYS_SEED_BYTES)
#define FILE_BYTES (CONTEXT_OFFSET + CRFPMOC_KEYS_CONTEXT_BYTES)

G_STATIC_ASSERT (MAGIC_BYTES == 8);

static gboolean
bytes_all_zero (const guint8 *data, gsize size)
{
  guint8 acc = 0;

  for (gsize i = 0; i < size; i++)
    acc |= data[i];

  return acc == 0;
}

/* Errors about an existing key file. The file is never replaced, because
 * every print enrolled on this machine is encrypted with these keys. */
static void
set_unusable_error (GError    **error,
                    GIOErrorEnum code,
                    const char  *path,
                    const char  *reason)
{
  g_set_error (error, G_IO_ERROR, code,
               "Cannot use the fingerprint machine key file %s: %s. "
               "Prints enrolled on this machine depend on it, so it was "
               "not replaced; restore it, or remove it and re-enroll all "
               "fingerprints",
               path, reason);
}

static void
set_create_error (GError **error, int errsv, const char *path, const char *what)
{
  g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errsv),
               "Cannot create the fingerprint machine key file %s: %s: %s",
               path, what, g_strerror (errsv));
}

/* Only trust a directory that is ours and that nobody else can write. */
static gboolean
check_directory (int dir_fd, const char *path, GError **error)
{
  struct stat st;

  if (fstat (dir_fd, &st) != 0)
    {
      int errsv = errno;

      set_unusable_error (error, g_io_error_from_errno (errsv), path,
                          g_strerror (errsv));
      return FALSE;
    }

  if (!S_ISDIR (st.st_mode) || st.st_uid != geteuid () || (st.st_mode & 022) != 0)
    {
      set_unusable_error (error, G_IO_ERROR_PERMISSION_DENIED, path,
                          "its directory is not private to this user");
      return FALSE;
    }

  return TRUE;
}

static gboolean
fsync_directory (const char *dir, GError **error)
{
  int fd = open (dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  int errsv;

  if (fd < 0)
    {
      errsv = errno;
      set_create_error (error, errsv, dir, "cannot open directory");
      return FALSE;
    }

  if (fsync (fd) != 0)
    {
      errsv = errno;
      close (fd);
      set_create_error (error, errsv, dir, "cannot sync directory");
      return FALSE;
    }

  close (fd);
  return TRUE;
}

/* Open the key directory without following a symlink, creating it 0700 if
 * it is missing and creation is allowed. Returns -1 with *missing set and
 * no error when it is missing and may not be created. */
static int
open_key_directory (const char *path,
                    const char *dir,
                    gboolean    may_create,
                    gboolean   *missing,
                    GError    **error)
{
  int fd;
  int errsv;

  *missing = FALSE;

  fd = open (dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0 && errno == ENOENT && may_create)
    {
      g_autofree char *parent = g_path_get_dirname (dir);

      if (mkdir (dir, 0700) != 0 && errno != EEXIST)
        {
          errsv = errno;
          set_create_error (error, errsv, path, "cannot create its directory");
          return -1;
        }

      if (!fsync_directory (parent, error))
        return -1;

      fd = open (dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }

  if (fd < 0)
    {
      errsv = errno;
      if (errsv == ENOENT && !may_create)
        *missing = TRUE;
      else
        set_unusable_error (error, g_io_error_from_errno (errsv), path,
                            "cannot open its directory");
      return -1;
    }

  if (!check_directory (fd, path, error))
    {
      close (fd);
      return -1;
    }

  return fd;
}

static gboolean
read_key_file (int         fd,
               const char *path,
               guint8      seed[CRFPMOC_KEYS_SEED_BYTES],
               guint8      context[CRFPMOC_KEYS_CONTEXT_BYTES],
               GError    **error)
{
  guint8 buf[FILE_BYTES];
  struct stat st;
  gsize got = 0;
  guint32 version;
  gboolean ok = FALSE;

  if (fstat (fd, &st) != 0)
    {
      int errsv = errno;

      set_unusable_error (error, g_io_error_from_errno (errsv), path, g_strerror (errsv));
      return FALSE;
    }

  if (!S_ISREG (st.st_mode))
    {
      set_unusable_error (error, G_IO_ERROR_INVALID_DATA, path, "not a regular file");
      return FALSE;
    }
  if (st.st_uid != geteuid ())
    {
      set_unusable_error (error, G_IO_ERROR_PERMISSION_DENIED, path,
                          "owned by another user");
      return FALSE;
    }
  if ((st.st_mode & 07177) != 0)
    {
      set_unusable_error (error, G_IO_ERROR_PERMISSION_DENIED, path,
                          "permissions are not 0600");
      return FALSE;
    }
  if (st.st_size != FILE_BYTES)
    {
      set_unusable_error (error, G_IO_ERROR_INVALID_DATA, path, "unexpected size");
      return FALSE;
    }

  while (got < FILE_BYTES)
    {
      gssize r = read (fd, buf + got, FILE_BYTES - got);

      if (r < 0 && errno == EINTR)
        continue;
      if (r <= 0)
        {
          set_unusable_error (error, r < 0 ? g_io_error_from_errno (errno) :
                              G_IO_ERROR_INVALID_DATA, path, "short read");
          goto out;
        }
      got += r;
    }

  version = (guint32) buf[MAGIC_BYTES] |
            ((guint32) buf[MAGIC_BYTES + 1] << 8) |
            ((guint32) buf[MAGIC_BYTES + 2] << 16) |
            ((guint32) buf[MAGIC_BYTES + 3] << 24);

  if (memcmp (buf, CRFPMOC_KEYS_MAGIC, MAGIC_BYTES) != 0)
    set_unusable_error (error, G_IO_ERROR_INVALID_DATA, path, "not a key file");
  else if (version != CRFPMOC_KEYS_VERSION)
    set_unusable_error (error, G_IO_ERROR_NOT_SUPPORTED, path,
                        "unsupported key file version");
  else if (bytes_all_zero (buf + SEED_OFFSET, CRFPMOC_KEYS_SEED_BYTES))
    set_unusable_error (error, G_IO_ERROR_INVALID_DATA, path, "the seed is all zero");
  else if (bytes_all_zero (buf + CONTEXT_OFFSET, CRFPMOC_KEYS_CONTEXT_BYTES))
    set_unusable_error (error, G_IO_ERROR_INVALID_DATA, path, "the context is all zero");
  else
    ok = TRUE;

  if (ok)
    {
      memcpy (seed, buf + SEED_OFFSET, CRFPMOC_KEYS_SEED_BYTES);
      memcpy (context, buf + CONTEXT_OFFSET, CRFPMOC_KEYS_CONTEXT_BYTES);
    }

out:
  explicit_bzero (buf, sizeof (buf));
  return ok;
}

static gboolean
fill_random (guint8 *data, gsize size, const char *path, GError **error)
{
  gsize got = 0;

  while (got < size)
    {
      gssize r = getrandom (data + got, size - got, 0);

      if (r < 0)
        {
          int errsv = errno;

          if (errsv == EINTR)
            continue;
          set_create_error (error, errsv, path, "cannot get random bytes");
          return FALSE;
        }
      got += r;
    }

  return TRUE;
}

static gboolean
write_all (int fd, const guint8 *data, gsize size)
{
  gsize done = 0;

  while (done < size)
    {
      gssize r = write (fd, data + done, size - done);

      if (r < 0 && errno == EINTR)
        continue;
      if (r <= 0)
        {
          if (r == 0)
            errno = EIO;
          return FALSE;
        }
      done += r;
    }

  return TRUE;
}

/* Write a new key file: random bytes into a private temporary file in the
 * same directory, synced, then renamed into place without replacing
 * anything, then the directory synced. */
static gboolean
create_key_file (int         dir_fd,
                 const char *path,
                 const char *dir,
                 const char *name,
                 guint8      seed[CRFPMOC_KEYS_SEED_BYTES],
                 guint8      context[CRFPMOC_KEYS_CONTEXT_BYTES],
                 GError    **error)
{
  guint8 buf[FILE_BYTES];
  g_autofree char *tmp_name = NULL;
  gboolean ok = FALSE;
  int fd = -1;
  int errsv;

  memcpy (buf, CRFPMOC_KEYS_MAGIC, MAGIC_BYTES);
  buf[MAGIC_BYTES] = CRFPMOC_KEYS_VERSION & 0xff;
  buf[MAGIC_BYTES + 1] = (CRFPMOC_KEYS_VERSION >> 8) & 0xff;
  buf[MAGIC_BYTES + 2] = (CRFPMOC_KEYS_VERSION >> 16) & 0xff;
  buf[MAGIC_BYTES + 3] = (CRFPMOC_KEYS_VERSION >> 24) & 0xff;

  if (!fill_random (buf + SEED_OFFSET,
                    CRFPMOC_KEYS_SEED_BYTES + CRFPMOC_KEYS_CONTEXT_BYTES,
                    path, error))
    goto out;

  /* The firmware rejects a trivial seed; a zero context leaves templates
   * undecryptable. Practically impossible from getrandom(), but check. */
  if (bytes_all_zero (buf + SEED_OFFSET, CRFPMOC_KEYS_SEED_BYTES) ||
      bytes_all_zero (buf + CONTEXT_OFFSET, CRFPMOC_KEYS_CONTEXT_BYTES))
    {
      set_create_error (error, EIO, path, "random bytes are all zero");
      goto out;
    }

  for (int attempt = 0; attempt < 100 && fd < 0; attempt++)
    {
      g_free (tmp_name);
      tmp_name = g_strdup_printf ("%s.tmp.%08x", name, g_random_int ());
      fd = openat (dir_fd, tmp_name,
                   O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
      if (fd < 0 && errno != EEXIST)
        break;
    }

  if (fd < 0)
    {
      errsv = errno;
      g_clear_pointer (&tmp_name, g_free);
      set_create_error (error, errsv, path, "cannot create a temporary file");
      goto out;
    }

  if (fchmod (fd, 0600) != 0 || !write_all (fd, buf, sizeof (buf)) || fsync (fd) != 0)
    {
      errsv = errno;
      set_create_error (error, errsv, path, "cannot write the temporary file");
      goto out;
    }

  if (close (g_steal_fd (&fd)) != 0)
    {
      errsv = errno;
      set_create_error (error, errsv, path, "cannot write the temporary file");
      goto out;
    }

  if (renameat2 (dir_fd, tmp_name, dir_fd, name, RENAME_NOREPLACE) != 0)
    {
      errsv = errno;
      set_create_error (error, errsv, path, "cannot move the new file into place");
      goto out;
    }
  g_clear_pointer (&tmp_name, g_free);

  if (fsync (dir_fd) != 0)
    {
      errsv = errno;
      set_create_error (error, errsv, dir, "cannot sync directory");
      goto out;
    }

  memcpy (seed, buf + SEED_OFFSET, CRFPMOC_KEYS_SEED_BYTES);
  memcpy (context, buf + CONTEXT_OFFSET, CRFPMOC_KEYS_CONTEXT_BYTES);
  ok = TRUE;

out:
  if (fd >= 0)
    close (fd);
  if (tmp_name)
    unlinkat (dir_fd, tmp_name, 0);
  explicit_bzero (buf, sizeof (buf));
  return ok;
}

/**
 * crfpmoc_keys_load_or_create:
 * @path: the key file
 * @may_create: whether a missing file may be created
 * @seed: (out): the seed, set on success only
 * @context: (out): the user context, set on success only
 * @created: (out): whether the file was created by this call
 * @error: return location for an error
 *
 * Loads the machine key file, or creates it if it is missing and
 * @may_create is set. An existing file that is not valid is an error and
 * is left alone. A missing file that may not be created is reported as
 * %G_IO_ERROR_NOT_FOUND and nothing is created.
 *
 * Returns: %TRUE on success
 */
gboolean
crfpmoc_keys_load_or_create (const char *path,
                             gboolean    may_create,
                             guint8      seed[CRFPMOC_KEYS_SEED_BYTES],
                             guint8      context[CRFPMOC_KEYS_CONTEXT_BYTES],
                             gboolean   *created,
                             GError    **error)
{
  g_autofree char *dir = g_path_get_dirname (path);
  g_autofree char *name = g_path_get_basename (path);
  gboolean missing;
  gboolean ok;
  int dir_fd;
  int fd;
  int errsv;

  g_return_val_if_fail (path != NULL && created != NULL, FALSE);

  dir_fd = open_key_directory (path, dir, may_create, &missing, error);
  if (dir_fd < 0)
    {
      if (missing)
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                     "The fingerprint machine key file %s does not exist", path);
      return FALSE;
    }

  fd = openat (dir_fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
  if (fd >= 0)
    {
      ok = read_key_file (fd, path, seed, context, error);
      close (fd);
      if (ok)
        *created = FALSE;
    }
  else if (errno == ENOENT && may_create)
    {
      ok = create_key_file (dir_fd, path, dir, name, seed, context, error);
      if (ok)
        *created = TRUE;
    }
  else if (errno == ENOENT)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                   "The fingerprint machine key file %s does not exist", path);
      ok = FALSE;
    }
  else
    {
      errsv = errno;
      set_unusable_error (error, g_io_error_from_errno (errsv), path,
                          errsv == ELOOP ? "it is a symbolic link" : g_strerror (errsv));
      ok = FALSE;
    }

  close (dir_fd);
  return ok;
}

/**
 * crfpmoc_keys_seed_action:
 * @key_is_new: the machine key was created now or does not exist yet, so
 *   the reader cannot hold its seed
 * @seed_needed: FP_ENC_STATUS reports the seed as not set
 * @send_seed: (out): whether FP_SEED must be sent
 * @error: return location for an error
 *
 * The FPMCU keeps the seed it was given until it reboots, and FP_SEED
 * cannot replace it. If the reader holds a seed and the machine key is new,
 * that seed is some other one (for example from a previous driver build):
 * templates would be encrypted with the wrong key, so refuse.
 *
 * Returns: %TRUE if the operation may continue
 */
gboolean
crfpmoc_keys_seed_action (gboolean  key_is_new,
                          gboolean  seed_needed,
                          gboolean *send_seed,
                          GError  **error)
{
  if (!seed_needed && key_is_new)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "The fingerprint reader already holds an encryption "
                           "seed that does not come from this machine's key; "
                           "reboot the computer to reset the reader, then try again");
      return FALSE;
    }

  *send_seed = seed_needed;
  return TRUE;
}
