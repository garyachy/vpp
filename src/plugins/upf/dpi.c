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
  hs_database_t *database;
  hs_scratch_t *scratch;
} upf_dpi_entry_t;

static upf_dpi_entry_t *upf_dpi_db = NULL;

int
upf_dpi_add_multi_regex(upf_dpi_args_t * args, u32 * db_index, u8 create)
{
  upf_dpi_entry_t *entry = NULL;
  hs_compile_error_t *compile_err = NULL;
  u32 *ids = NULL;
  const char **expressions = NULL;
  u32 *flags = NULL;
  upf_dpi_args_t *arg = NULL;
  int error = 0;

  if (!args)
    return -1;

  if (vec_len(args) == 0)
    return -1;

  if (!create)
    {
      entry = pool_elt_at_index (upf_dpi_db, * db_index);
      if (!entry)
        return -1;

      if (entry->database)
        {
          hs_free_database(entry->database);
          entry->database = NULL;
        }
    }
  else
    {
      pool_get (upf_dpi_db, entry);
      if (!entry)
        return -1;
 
      memset(entry, 0, sizeof(*entry));
      *db_index = entry - upf_dpi_db;
    }

  vec_foreach (arg, args)
    {
      vec_add1(ids, arg->index);
      vec_add1(expressions, (const char*)arg->rule);
      vec_add1(flags, HS_FLAG_DOTALL);
    }

  if (hs_compile_multi(expressions, flags, ids, vec_len(args),
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
  vec_free(expressions);
  vec_free(flags);
  vec_free(ids);

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

  u32 *app_id = (u32*)ctx;

  *app_id = id;

  return 0;
}

int
upf_dpi_lookup(u32 db_index, u8 * str, uint16_t length, u32 * app_index)
{
  upf_dpi_entry_t *entry = NULL;
  int ret = 0;

  if (!upf_dpi_db)
    return -1;

  entry = pool_elt_at_index (upf_dpi_db, db_index);
  if (!entry)
    return -1;

  ret = hs_scan(entry->database, (const char*)str, length, 0, entry->scratch,
                upf_dpi_event_handler, (void*)app_index);
    if (ret != HS_SUCCESS)
    {
      return -1;
    }

  return 0;
}

int
upf_dpi_remove(u32 db_index)
{
  upf_dpi_entry_t *entry = NULL;

  entry = pool_elt_at_index (upf_dpi_db, db_index);
  if (!entry)
    return -1;

  if (entry->database)
    {
      hs_free_database(entry->database);
      entry->database = NULL;
    }

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
