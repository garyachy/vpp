/*
 * dpi.c - 3GPP TS 29.244 UPF DPI
 *
 * Copyright (c) 2017 Travelping GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _LGPL_SOURCE            /* LGPL v3.0 is compatible with Apache 2.0 */

#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vppinfra/pool.h>

#include <hs.h>
#include "upf/dpi.h"

typedef struct {
  regex_t *expressions;
  u32 *ids;
  u32 *flags;
  hs_database_t *database;
  hs_scratch_t *scratch;
} upf_dpi_entry_t;

typedef struct {
  int res;
  u32 id;
} upf_dpi_cb_args_t;

static upf_dpi_entry_t *upf_dpi_db = NULL;

int
upf_dpi_get_db_contents(u32 db_index, regex_t ** expressions, u32 ** ids)
{
  upf_dpi_entry_t *entry = NULL;

  if (!db_index)
    return -1;

  if (pool_elts(upf_dpi_db) < db_index)
    return -1;

  db_index -= 1;

  entry = pool_elt_at_index (upf_dpi_db, db_index);
  if (!entry)
    return -1;

  *expressions = entry->expressions;
  *ids = entry->ids;

  return 0;
}

int
upf_dpi_add_multi_regex(upf_dpi_args_t * args, u32 * db_index, u8 create)
{
  upf_dpi_entry_t *entry = NULL;
  hs_compile_error_t *compile_err = NULL;
  upf_dpi_args_t *arg = NULL;
  int error = 0;
  u32 index = 0;

  if (!args)
    return -1;

  if (vec_len(args) == 0)
    return -1;

  if (!create)
    {
      if (!*db_index)
        return -1;

      if (pool_elts(upf_dpi_db) < *db_index)
        return -1;

      index = *db_index - 1;
      entry = pool_elt_at_index (upf_dpi_db, index);
      if (!entry)
        return -1;

      hs_free_database(entry->database);
      entry->database = NULL;
      hs_free_scratch(entry->scratch);
      entry->scratch = NULL;
    }
  else
    {
      pool_get (upf_dpi_db, entry);
      if (!entry)
        return -1;

      memset(entry, 0, sizeof(*entry));
      index = entry - upf_dpi_db;
      *db_index = index + 1;
    }

  vec_foreach (arg, args)
    {
      vec_add1(entry->ids, arg->index);
      vec_add1(entry->expressions, arg->rule);
      vec_add1(entry->flags, HS_FLAG_DOTALL);
    }

  if (hs_compile_multi((const char **)entry->expressions, entry->flags, entry->ids,
                       vec_len(entry->expressions),
                       HS_MODE_BLOCK, NULL, &entry->database,
                       &compile_err) != HS_SUCCESS)
    {
      error = -1;
      goto done;
    }

  if (hs_alloc_scratch(entry->database, &entry->scratch) != HS_SUCCESS)
    {
      hs_free_database(entry->database);
      entry->database = NULL;
      error = -1;
      goto done;
    }

done:
  return error;
}

static int
upf_dpi_event_handler(unsigned int id, unsigned long long from,
                                 unsigned long long to, unsigned int flags,
                                void *ctx)
{
  (void) from;
  (void) to;
  (void) flags;

  upf_dpi_cb_args_t *args = (upf_dpi_cb_args_t*)ctx;

  args->id = id;
  args->res = 1;

  return 0;
}

int
upf_dpi_lookup(u32 db_index, u8 * str, uint16_t length, u32 * app_index)
{
  upf_dpi_entry_t *entry = NULL;
  int ret = 0;
  upf_dpi_cb_args_t args = {};

  if (!db_index)
    return -1;

  if (pool_elts(upf_dpi_db) < db_index)
    return -1;

  db_index -= 1;

  entry = pool_elt_at_index (upf_dpi_db, db_index);
  if (!entry)
    return -1;

  ret = hs_scan(entry->database, (const char*)str, length, 0, entry->scratch,
                upf_dpi_event_handler, (void*)&args);
  if (ret != HS_SUCCESS)
    return -1;

  if (args.res == 0)
    return -1;

  *app_index = args.id;

  return 0;
}

int
upf_dpi_remove(u32 db_index)
{
  upf_dpi_entry_t *entry = NULL;

  if (!db_index)
    return -1;

  if (pool_elts(upf_dpi_db) < db_index)
    return -1;

  db_index -= 1;

  entry = pool_elt_at_index (upf_dpi_db, db_index);
  if (!entry)
    return -1;

  hs_free_database(entry->database);
  hs_free_scratch(entry->scratch);
  vec_free(entry->expressions);
  vec_free(entry->flags);
  vec_free(entry->ids);

  memset(entry, 0, sizeof(upf_dpi_entry_t));

  pool_put (upf_dpi_db, entry);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
