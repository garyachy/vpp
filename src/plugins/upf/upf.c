/*
 * upf.c - 3GPP TS 29.244 GTP-U UP plug-in for vpp
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
#include <urcu-qsbr.h>          /* QSBR RCU flavor */

#include <rte_config.h>
#include <rte_common.h>
#include <rte_eal.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <upf/upf.h>
#include <upf/upf_pfcp.h>
#include <upf/pfcp.h>
#include <upf/upf_pfcp_server.h>

#include "flowtable.h"
#include <upf/flowtable_impl.h>
#include <upf/dpi.h>

static void
foreach_upf_flows (BVT (clib_bihash_kv) * kvp, void * arg);

static void
upf_add_rules(u32 app_index, upf_dpi_app_t *app, upf_dpi_args_t ** args)
{
  u32 index = 0;
  u32 rule_index = 0;
  upf_dpi_rule_t *rule = NULL;
  upf_dpi_args_t arg;

  /* *INDENT-OFF* */
  hash_foreach(rule_index, index, app->rules_by_id,
  ({
     rule = pool_elt_at_index(app->rules, index);

     if (rule->path)
       {
         arg.index = app_index;
         arg.rule = rule->path;
         vec_add1(*args, arg);
       }
  }));
  /* *INDENT-ON* */
}

int
upf_add_multi_regex(u8 ** apps, u32 * db_index, u8 create)
{
  uword *p = NULL;
  u8 **app_name = NULL;
  u32 index = 0;
  upf_dpi_args_t *args = NULL;
  upf_main_t * sm = &upf_main;
  upf_dpi_app_t *app = NULL;
  int res = 0;

  vec_foreach (app_name, apps)
    {
      p = hash_get_mem (sm->upf_app_by_name, *app_name);

      if (p)
        {
          app = pool_elt_at_index(sm->upf_apps, p[0]);
          upf_add_rules(index, app, &args);
        }
    }

  if (!args)
    return -1;

  res = upf_dpi_add_multi_regex(args, db_index, create);
  vec_free(args);

  return res;
}

static clib_error_t *
upf_dpi_app_add_command_fn (vlib_main_t * vm,
                            unformat_input_t * input,
                            vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  clib_error_t *error = NULL;
  u8 **apps = NULL;
  u32 id = 0;
  int res = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%s", &name))
        {
          break;
        }
      else
        {
          error = clib_error_return (0, "unknown input `%U'",
          format_unformat_error, input);
          goto done;
        }
    }

  vec_add1(apps, name);
  res = upf_add_multi_regex(apps, &id, 1);
  vec_free(apps);

  if (res == 0)
    vlib_cli_output (vm, "DB id %u", id);
  else
    vlib_cli_output (vm, "Could not build DPI DB  ");

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_dpi_app_add_command, static) =
{
  .path = "upf dpi app add",
  .short_help = "upf dpi app add <name>",
  .function = upf_dpi_app_add_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_dpi_url_test_command_fn (vlib_main_t * vm,
                             unformat_input_t * input,
                             vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *url = NULL;
  clib_error_t *error = NULL;
  u32 app_index = 0;
  u32 id = 0;
  int res = 0;
  upf_dpi_app_t *app = NULL;
  upf_main_t * sm = &upf_main;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u url %s", &id, &url))
        {
          break;
        }
      else
        {
          error = clib_error_return (0, "unknown input `%U'",
          format_unformat_error, input);
          goto done;
        }
    }

  res = upf_dpi_lookup(id, url, vec_len(url), &app_index);
  if (res == 0)
    {
      app = pool_elt_at_index (sm->upf_apps, app_index);
      if (app)
        vlib_cli_output (vm, "Matched app: %s", app->name);
    }
  else
    {
      vlib_cli_output (vm, "No match found");
    }

done:
  vec_free (url);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_dpi_url_test_command, static) =
{
  .path = "upf dpi test db",
  .short_help = "upf dpi test db <id> url <url>",
  .function = upf_dpi_url_test_command_fn,
};
/* *INDENT-ON* */

/* Action function shared between message handler and debug CLI */

static int
vnet_upf_rule_add_del(u8 * app_name, u32 rule_index, u8 add,
                      upf_rule_args_t * args);

static int
vnet_upf_app_add_del(u8 * name, u8 add);

int upf_app_add_del (upf_main_t * sm, u8 * name, int add)
{
  int rv = 0;

  rv = vnet_upf_app_add_del(name, add);

  return rv;
}

int upf_rule_add_del (upf_main_t * sm, u8 * name, u32 id,
                      int add, upf_rule_args_t * args)
{
  int rv = 0;

  rv = vnet_upf_rule_add_del(name, id, add, args);

  return rv;
}

int upf_enable_disable (upf_main_t * sm, u32 sw_if_index,
			  int enable_disable)
{
  vnet_sw_interface_t * sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (sm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("device-input", "upf",
			       sw_if_index, enable_disable, 0, 0);

  return rv;
}

static clib_error_t *
upf_enable_disable_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  upf_main_t * sm = &upf_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 sm->vnet_main, &sw_if_index))
	;
      else
	break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = upf_enable_disable (sm, sw_if_index, enable_disable);

  switch(rv)
    {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  default:
    return clib_error_return (0, "upf_enable_disable returned %d",
			      rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_enable_disable_command, static) =
{
  .path = "upf enable-disable",
  .short_help =
  "upf enable-disable <interface-name> [disable]",
  .function = upf_enable_disable_command_fn,
};
/* *INDENT-ON* */

int vnet_upf_nwi_add_del(u8 * name, u8 add)
{
  upf_main_t * gtm = &upf_main;
  upf_nwi_t * nwi;
  uword *p;

  p = hash_get_mem (gtm->nwi_index_by_name, name);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get_aligned (gtm->nwis, nwi, CLIB_CACHE_LINE_BYTES);
      memset (nwi, 0, sizeof (*nwi));

      nwi->name = vec_dup(name);

      for (int i = 0; i < ARRAY_LEN(nwi->intf_sw_if_index); i++)
	nwi->intf_sw_if_index[i] = ~0;

      hash_set_mem (gtm->nwi_index_by_name, nwi->name, nwi - gtm->nwis);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      nwi = pool_elt_at_index (gtm->nwis, p[0]);

      hash_unset_mem (gtm->nwi_index_by_name, nwi->name);
      vec_free (nwi->name);
      pool_put (gtm->nwis, nwi);
     }

  return 0;
}

/**
 * Translate "foo.com" into "0x3 f o o 0x3 c o m 0x0"
 * A historical / hysterical micro-TLV scheme. DGMS.
 */
static u8 *
upf_name_to_labels (u8 * name)
{
  int i;
  int last_label_index;
  u8 *rv;

  rv = vec_dup (name);

  /* punch in space for the first length */
  vec_insert (rv, 1, 0);
  last_label_index = 0;
  i = 1;

  while (i < vec_len (rv))
    {
      if (rv[i] == '.')
	{
	  rv[last_label_index] = (i - last_label_index) - 1;
	  if ((i - last_label_index) > 63)
	    clib_warning ("stupid name, label length %d",
			  i - last_label_index);
	  last_label_index = i;
	  rv[i] = 0;
	}
      i++;
    }
  /* Set the last real label length */
  rv[last_label_index] = (i - last_label_index) - 1;

  return rv;
}

static clib_error_t *
upf_nwi_add_del_command_fn (vlib_main_t * vm,
			      unformat_input_t * main_input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t * error = NULL;
  u8 *name = NULL;
  u8 *label = NULL;
  u8 add = 1;
  int rv;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "name %_%v%_", &name))
	;
      else if (unformat (line_input, "label %_%v%_", &label))
	;
      else {
	error = unformat_parse_error (line_input);
	goto done;
      }
    }

  if (!name && !label)
    return clib_error_return (0, "name or label must be specified!");

  if (!name)
    name = upf_name_to_labels(label);

  rv = vnet_upf_nwi_add_del(name, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "network instance already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "network instance does not exist...");
      break;

    default:
      error = clib_error_return
	(0, "vnet_upf_nwi_add_del returned %d", rv);
      break;
    }

done:
  vec_free (name);
  vec_free (label);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_nwi_add_del_command, static) =
{
  .path = "upf nwi create",
  .short_help =
  "upf nwi create [name <name> | dns <label>]",
  .function = upf_nwi_add_del_command_fn,
};
/* *INDENT-ON* */

#if 0
static void vtep_ip4_ref(ip4_address_t * ip, u8 ref)
{
  uword *vtep = hash_get (upf_main.vtep4, ip->as_u32);
  if (ref)
    {
      if (vtep)
	++(*vtep);
      else
	hash_set (upf_main.vtep4, ip->as_u32, 1);
    }
  else
    {
      if (!vtep)
	return;

      if (--(*vtep) == 0)
	hash_unset (upf_main.vtep4, ip->as_u32);
    }
}

static void vtep_ip6_ref(ip6_address_t * ip, u8 ref)
{
  uword *vtep = hash_get_mem (upf_main.vtep6, ip);
  if (ref)
    {
      if (vtep)
	++(*vtep);
      else
	hash_set_mem_alloc (&upf_main.vtep6, ip, 1);
    }
  else
    {
      if (!vtep)
	return;

      if (--(*vtep) == 0)
	hash_unset_mem_free (&upf_main.vtep6, ip);
    }
}

static void vtep_if_address_add_del(u32 sw_if_index, u8 add)
{
  ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
  ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
  ip_interface_address_t *ia = 0;
  ip4_address_t *ip4;
  ip6_address_t *ip6;

  foreach_ip_interface_address (lm4, ia, sw_if_index, 1 /* unnumbered */ ,
  ({
    ip4 = ip_interface_address_get_address (lm4, ia);
    vtep_ip4_ref(ip4, add);
  }));
  foreach_ip_interface_address (lm6, ia, sw_if_index, 1 /* unnumbered */ ,
  ({
    ip6 = ip_interface_address_get_address (lm6, ia);
    vtep_ip6_ref(ip6, add);
  }));
}
#endif

int vnet_upf_nwi_set_addr(u8 * name, ip46_address_t *ip, u32 teid, u32 mask, u8 add)
{
  upf_main_t * gtm = &upf_main;
  upf_nwi_ip_res_t *ip_res;
  upf_nwi_t * nwi;
  uword *p;

  p = hash_get_mem (gtm->nwi_index_by_name, name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  nwi = pool_elt_at_index (gtm->nwis, p[0]);
  if (!nwi->ip_res_index_by_ip)
    nwi->ip_res_index_by_ip =
      hash_create_mem (0, sizeof (ip46_address_t), sizeof (uword));

  p = hash_get_mem (nwi->ip_res_index_by_ip, ip);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get_aligned (nwi->ip_res, ip_res, CLIB_CACHE_LINE_BYTES);
      memset (ip_res, 0, sizeof (*ip_res));

      ip_res->ip = *ip;
      ip_res->teid = teid & mask;
      ip_res->mask = mask;

      hash_set_mem_alloc(&nwi->ip_res_index_by_ip, &ip_res->ip, ip_res - nwi->ip_res);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      ip_res = pool_elt_at_index (nwi->ip_res, p[0]);
      hash_unset_mem_free (&nwi->ip_res_index_by_ip, &ip_res->ip);
      pool_put(nwi->ip_res, ip_res);
    }

  return 0;
}

clib_error_t *
upf_nwi_set_addr_command_fn (vlib_main_t * vm,
			       unformat_input_t * main_input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t * error = NULL;
  u32 addr_set = 0;
  ip46_address_t ip;
  u32 teid = 0, mask = 0, teidri = 0;
  u8 *name = NULL;
  u8 *label = NULL;
  u8 add = 1;
  int rv;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "name %_%v%_", &name))
	;
      else if (unformat (line_input, "label %_%v%_", &label))
	;
      else if (unformat (line_input, "%U", unformat_ip46_address, &ip, IP46_TYPE_ANY))
	addr_set = 1;
      else if (unformat (line_input, "teid %u/%u", &teid, &teidri))
	{
	  if (teidri > 7) {
	    error = clib_error_return (0, "TEID Range Indication to large (%d > 7)", teidri);
	    goto done;
	  }
	  mask = 0xfe000000 << (7 - teidri);
	}
      else if (unformat (line_input, "teid 0x%x/%u", &teid, &teidri))
	{
	  if (teidri > 7) {
	    error = clib_error_return (0, "TEID Range Indication to large (%d > 7)", teidri);
	    goto done;
	  }
	  mask = 0xfe000000 << (7 - teidri);
	}
      else {
	error = unformat_parse_error (line_input);
	goto done;
      }
    }

  if (!addr_set)
    {
      error = clib_error_return (0, "No IP address provided");
      goto done;
    }
  if (!name && !label)
    {
      error = clib_error_return (0, "name or label must be specified");
      goto done;
    }

  if (!name)
    name = upf_name_to_labels(label);

  rv = vnet_upf_nwi_set_addr(name, &ip, teid, mask, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "IP resource already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "network instance or IP resource does not exist...");
      break;

    default:
      error = clib_error_return
	(0, "vnet_upf_nwi_set_addr returned %d", rv);
      break;
    }

 done:
  vec_free (name);
  vec_free (label);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_nwi_set_addr_command, static) =
{
  .path = "upf nwi set gtpu address",
  .short_help =
  "upf nwi set gtpu address [name <name> | dns <label>] <address> [teid <teid>/<mask>] [del]",
  .function = upf_nwi_set_addr_command_fn,
};
/* *INDENT-ON* */

int vnet_upf_nwi_set_intf_role(u8 * name, u8 intf, u32 sw_if_index, u8 add)
{
  upf_main_t * gtm = &upf_main;
  upf_nwi_t * nwi;
  u32 nwi_index;
  uword *p;

  if (intf >= INTF_NUM)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  p = hash_get_mem (gtm->nwi_index_by_name, name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  nwi_index = p[0];
  nwi = pool_elt_at_index (gtm->nwis, nwi_index);

  if (add)
    {
      if (sw_if_index < vec_len(gtm->nwi_index_by_sw_if_index) &&
	  gtm->nwi_index_by_sw_if_index[sw_if_index] != ~0)
	return VNET_API_ERROR_VALUE_EXIST;

      vec_validate_init_empty(gtm->nwi_index_by_sw_if_index, sw_if_index, ~0);
      vec_validate_init_empty(gtm->intf_type_by_sw_if_index, sw_if_index, ~0);
      gtm->nwi_index_by_sw_if_index[sw_if_index] = nwi_index;
      gtm->intf_type_by_sw_if_index[sw_if_index] = intf;
      nwi->intf_sw_if_index[intf] = sw_if_index;
    }
  else
    {
      if (sw_if_index > vec_len(gtm->nwi_index_by_sw_if_index) ||
	  gtm->nwi_index_by_sw_if_index[sw_if_index] != nwi_index)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      gtm->nwi_index_by_sw_if_index[sw_if_index] = ~0;
      gtm->intf_type_by_sw_if_index[sw_if_index] = ~0;
      nwi->intf_sw_if_index[intf] = ~0;
    }

  return 0;
}

clib_error_t *
upf_nwi_set_intf_role_command_fn (vlib_main_t * vm,
				    unformat_input_t * main_input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t * error = NULL;
  u8 *name = NULL;
  u8 *label = NULL;
  u8 intf = ~0;
  u32 sw_if_index = ~0;
  u8 add = 1;
  int rv;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "name %_%v%_", &name))
	;
      else if (unformat (line_input, "label %_%v%_", &label))
	;
      else if (unformat (line_input, "interface %U",
			   unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "access"))
	intf = INTF_ACCESS;
      else if (unformat (line_input, "core"))
	intf = INTF_CORE;
      else if (unformat (line_input, "sgi"))
	intf = INTF_SGI_LAN;
      else if (unformat (line_input, "cp"))
	intf = INTF_CP;
      else if (unformat (line_input, "li"))
	intf = INTF_LI;
      else {
	error = unformat_parse_error (line_input);
	goto done;
      }
    }

  if (intf == (u8)~0)
    {
      error = clib_error_return (0, "Interface type not specified");
      goto done;
    }
  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "Interface or sw_if_index not specified");
      goto done;
    }
  if (!name && !label)
    {
      error = clib_error_return (0, "name or label must be specified");
      goto done;
    }

  if (!name)
    name = upf_name_to_labels(label);

  rv = vnet_upf_nwi_set_intf_role(name, intf, sw_if_index, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "network instance does not exist...");
      break;

    default:
      error = clib_error_return
	(0, "vnet_upf_nwi_set_intf_role returned %d", rv);
      break;
    }

 done:
  vec_free (name);
  vec_free (label);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_nwi_set_intf_role_command, static) =
{
  .path = "upf nwi set interface type",
  .short_help =
  "upf nwi set interface type [name <name> | dns <label>] [access | core | sgi | cp] [interface <interface> | sw_if_index <inde>] [del]",
  .function = upf_nwi_set_intf_role_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_nwi_command_fn (vlib_main_t * vm,
			   unformat_input_t * main_input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  upf_main_t * gtm = &upf_main;
  clib_error_t * error = NULL;
  upf_nwi_t * nwi;
  u8 *label = NULL;
  u8 *name = NULL;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "name %_%v%_", &name))
	    ;
	  else if (unformat (line_input, "label %_%v%_", &label))
	    ;
	  else {
	    error = unformat_parse_error (line_input);
	    unformat_free (line_input);
	    goto done;
	  }
	}

      unformat_free (line_input);
    }

  if (!name && label)
    name = upf_name_to_labels(label);

  pool_foreach (nwi, gtm->nwis,
    ({
      upf_nwi_ip_res_t * ip_res;

      if (name && !vec_is_equal(name, nwi->name))
	continue;

      vlib_cli_output (vm, "%U", format_network_instance, nwi->name);
      vlib_cli_output (vm, "  Access: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_ACCESS]);
      vlib_cli_output (vm, "  Core: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_CORE]);
      vlib_cli_output (vm, "  SGi LAN: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_SGI_LAN]);
      vlib_cli_output (vm, "  CP: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_CP]);
      vlib_cli_output (vm, "  LI: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_LI]);

      vlib_cli_output (vm, "  IPs: %d", pool_elts(nwi->ip_res));

      pool_foreach (ip_res, nwi->ip_res,
	({
	  vlib_cli_output (vm, "  [%d]: IP: %U, teid: 0x%08x/%d (0x%08x)",
			   ip_res - nwi->ip_res,
			   format_ip46_address, &ip_res->ip, IP46_TYPE_ANY,
			   ip_res->teid, __builtin_popcount(ip_res->mask),
			   ip_res->mask);
	}));
    }));

done:
  vec_free (name);
  vec_free (label);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_nwi_command, static) =
{
  .path = "show upf nwi",
  .short_help =
  "show upf nwi",
  .function = upf_show_nwi_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_session_command_fn (vlib_main_t * vm,
			       unformat_input_t * main_input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t * gtm = &upf_main;
  clib_error_t * error = NULL;
  u64 cp_seid, up_seid;
  ip46_address_t cp_ip;
  u8 has_cp_f_seid = 0, has_up_seid = 0;
  upf_session_t *sess;
  flowtable_main_t *fm = &flowtable_main;
  flowtable_per_session_t *fmt = NULL;
  u32 session_id = 0;
  u8 has_flows = 0;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "cp %U seid %lu",
			unformat_ip46_address, &cp_ip, IP46_TYPE_ANY, &cp_seid))
	    has_cp_f_seid = 1;
	  else if (unformat (line_input, "cp %U seid 0x%lx",
			     unformat_ip46_address, &cp_ip, IP46_TYPE_ANY, &cp_seid))
	    has_cp_f_seid = 1;
	  else if (unformat (line_input, "up seid %lu", &up_seid))
	    has_up_seid = 1;
	  else if (unformat (line_input, "up seid 0x%lx", &up_seid))
	    has_up_seid = 1;
		else if (unformat (line_input, "%u flows", &session_id))
	    has_flows = 1;
	  else {
	    error = unformat_parse_error (line_input);
	    unformat_free (line_input);
	    goto done;
	  }
	}

      unformat_free (line_input);
    }

  if (has_cp_f_seid)
    {
      error = clib_error_return (0, "CP F_SEID is not supported, yet");
      goto done;
    }

  if (has_up_seid)
    {
      if (!(sess = sx_lookup(up_seid)))
	{
	  error = clib_error_return (0, "Sessions %d not found", up_seid);
	  goto done;
	}

      vlib_cli_output (vm, "%U", format_sx_session, sess, SX_ACTIVE);
    }
  else
      pool_foreach (sess, gtm->sessions,
	({
	  vlib_cli_output (vm, "%U", format_sx_session, sess, SX_ACTIVE);
	}));

  if (has_flows)
    {
      fmt = &fm->per_session[session_id];
      if (fmt == NULL)
        {
          error = clib_error_return (0, "session id does not exist");
          goto done;
        }
    
      BV (clib_bihash_foreach_key_value_pair) (&fmt->flows_ht,
                                               foreach_upf_flows, vm);
    }

 done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_session_command, static) =
{
  .path = "show upf session",
  .short_help =
  "show upf session",
  .function = upf_show_session_command_fn,
};
/* *INDENT-ON* */

static int
vnet_upf_app_add_del(u8 * name, u8 add)
{
  upf_main_t *sm = &upf_main;
  upf_dpi_app_t *app = NULL;
  u32 index = 0;
  u32 rule_index = 0;
  uword *p = NULL;

  p = hash_get_mem (sm->upf_app_by_name, name);

  if (add)
    {
      if (p)
        return VNET_API_ERROR_VALUE_EXIST;

      pool_get (sm->upf_apps, app);
      memset(app, 0, sizeof(*app));

      app->name = vec_dup(name);
      app->rules_by_id = hash_create_mem (0, sizeof (u32), sizeof (uword));

      hash_set_mem (sm->upf_app_by_name, app->name, app - sm->upf_apps);
    }
  else
    {
      if (!p)
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      hash_unset_mem (sm->upf_app_by_name, name);
      app = pool_elt_at_index (sm->upf_apps, p[0]);

      /* *INDENT-OFF* */
      hash_foreach(rule_index, index, app->rules_by_id,
      ({
         upf_dpi_rule_t *rule = NULL;
         rule = pool_elt_at_index(app->rules, index);
         vnet_upf_rule_add_del(app->name, rule->id, 0, NULL);
      }));
      /* *INDENT-ON* */

      vec_free (app->name);
      hash_free(app->rules_by_id);
      pool_free(app->rules);
      pool_put (sm->upf_apps, app);
    }

  return 0;
}

static clib_error_t *
upf_create_app_command_fn (vlib_main_t * vm,
                           unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  clib_error_t *error = NULL;
  int rv = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%s", &name))
        break;
      else
        {
          error = unformat_parse_error (line_input);
          goto done;
        }
    }

  rv = vnet_upf_app_add_del(name, 1);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "application already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "application does not exist...");
      break;

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_create_app_command, static) =
{
  .path = "create upf application",
  .short_help = "create upf application <name>",
  .function = upf_create_app_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_delete_app_command_fn (vlib_main_t * vm,
                           unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  clib_error_t *error = NULL;
  int rv = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%s", &name))
        break;
      else
        {
          error = unformat_parse_error (line_input);
          goto done;
        }
    }

  rv = vnet_upf_app_add_del(name, 0);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "application already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "application does not exist...");
      break;

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_delete_app_command, static) =
{
  .path = "delete upf application",
  .short_help = "delete upf application <name>",
  .function = upf_delete_app_command_fn,
};
/* *INDENT-ON* */

static int
vnet_upf_rule_add_del(u8 * app_name, u32 rule_index, u8 add,
                      upf_rule_args_t * args)
{
  upf_main_t *sm = &upf_main;
  uword *p = NULL;
  upf_dpi_app_t *app = NULL;
  upf_dpi_rule_t *rule = NULL;

  p = hash_get_mem (sm->upf_app_by_name, app_name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  app = pool_elt_at_index (sm->upf_apps, p[0]);

  p = hash_get_mem (app->rules_by_id, &rule_index);

  if (add)
    {
      if (p)
        return VNET_API_ERROR_VALUE_EXIST;

      pool_get (app->rules, rule);
      memset(rule, 0, sizeof(*rule));
      rule->id = rule_index;
      rule->host = vec_dup(args->host);
      rule->path = vec_dup(args->path);

      hash_set_mem (app->rules_by_id,
                    &rule_index, rule - app->rules);
    }
  else
    {
      if (!p)
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      rule = pool_elt_at_index (app->rules, p[0]);
      vec_free(rule->host);
      vec_free(rule->path);
      hash_unset_mem (app->rules_by_id, &rule_index);
      pool_put (app->rules, rule);
    }

  return 0;
}

static clib_error_t *
upf_application_rule_add_del_command_fn (vlib_main_t * vm,
                                         unformat_input_t * input,
                                         vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *app_name = NULL;
  u8 *src_ip = NULL;
  u8 *dst_ip = NULL;
  u8 *host = NULL;
  u8 *path = NULL;
  u32 rule_index = 0;
  clib_error_t *error = NULL;
  int rv = 0;
  int add = 1;
  upf_rule_args_t rule_args = {};

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%s rule %u",
                    &app_name, &rule_index))
        {
          if (unformat (line_input, "del"))
            {
              add = 0;
              break;
            }
          else if (unformat (line_input, "add"))
            {
              add = 1;

              if (unformat (line_input, "ip dst %s", &dst_ip))
                break;
              else if (unformat (line_input, "ip src %s", &src_ip))
                break;
              else if (unformat (line_input, "l7 http host %s", &host))
                {
                  if (unformat (line_input, "path %s", &path))
                    break;
                }
              else
                {
                  error = clib_error_return (0, "unknown input `%U'",
                                             format_unformat_error, input);
                  goto done;
                }
            }
          else
            {
              error = clib_error_return (0, "unknown input `%U'",
                                         format_unformat_error, input);
              goto done;
            }
        }
      else
        {
          error = clib_error_return (0, "unknown input `%U'",
                                     format_unformat_error, input);
          goto done;
        }
    }

  rule_args.host = host;
  rule_args.path = path;
  rule_args.src_ip = src_ip;
  rule_args.dst_ip = dst_ip;

  rv = vnet_upf_rule_add_del(app_name, rule_index, add, &rule_args);
  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "rule already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "application or rule does not exist...");
      break;

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

done:
  vec_free (dst_ip);
  vec_free (src_ip);
  vec_free (host);
  vec_free (path);
  vec_free (app_name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_application_rule_add_del_command, static) =
{
  .path = "upf application",
  .short_help = "upf application <name> rule <id> (add | del) [ip src <ip> | dst <ip>] [l7 http host <regex> path <path>] ",
  .function = upf_application_rule_add_del_command_fn,
};
/* *INDENT-ON* */

static void
upf_show_rules(vlib_main_t * vm, upf_dpi_app_t * app)
{
  u32 index = 0;
  u32 rule_index = 0;
  upf_dpi_rule_t *rule = NULL;

  /* *INDENT-OFF* */
  hash_foreach(rule_index, index, app->rules_by_id,
  ({
     rule = pool_elt_at_index(app->rules, index);
     vlib_cli_output (vm, "rule: %u", rule->id);

     if (rule->host)
       vlib_cli_output (vm, "host: %s", rule->host);

     if (rule->path)
       vlib_cli_output (vm, "path: %s", rule->path);
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
upf_show_app_command_fn (vlib_main_t * vm,
                         unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  uword *p = NULL;
  clib_error_t *error = NULL;
  upf_dpi_app_t *app = NULL;
  upf_main_t * sm = &upf_main;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%s", &name))
        {
          break;
        }
      else
        {
          error = clib_error_return (0, "unknown input `%U'",
          format_unformat_error, input);
          goto done;
        }
    }

  p = hash_get_mem (sm->upf_app_by_name, name);
  if (!p)
    {
      error = clib_error_return (0, "unknown application name");
      goto done;
    }

  app = pool_elt_at_index (sm->upf_apps, p[0]);

  upf_show_rules(vm, app);

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_app_command, static) =
{
  .path = "show upf application",
  .short_help = "show upf application <name>",
  .function = upf_show_app_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_apps_command_fn (vlib_main_t * vm,
                          unformat_input_t * input,
                          vlib_cli_command_t * cmd)
{
  upf_main_t * sm = &upf_main;
  u8 *name = NULL;
  u32 index = 0;
  int verbose = 0;
  clib_error_t *error = NULL;
  unformat_input_t _line_input, *line_input = &_line_input;

  /* Get a line of input. */
  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "verbose"))
            {
              verbose = 1;
              break;
            }
          else
            {
              error = clib_error_return (0, "unknown input `%U'",
                                         format_unformat_error, input);
              unformat_free (line_input);
              return error;
            }
        }

      unformat_free (line_input);
    }

  /* *INDENT-OFF* */
  hash_foreach(name, index, sm->upf_app_by_name,
  ({
     upf_dpi_app_t *app = NULL;
     app = pool_elt_at_index(sm->upf_apps, index);
     vlib_cli_output (vm, "app: %s", app->name);

     if (verbose)
       {
         upf_show_rules(vm, app);
       }
  }));
  /* *INDENT-ON* */

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_apps_command, static) =
{
  .path = "show upf applications",
  .short_help = "show upf applications [verbose]",
  .function = upf_show_apps_command_fn,
};
/* *INDENT-ON* */

static void
foreach_upf_flows (BVT (clib_bihash_kv) * kvp, void * arg)
{
  dlist_elt_t *ht_line = NULL;
  u32 index = 0;
  flow_entry_t *flow = NULL;
  vlib_main_t *vm = arg;
  u32 ht_line_head_index = (u32) kvp->value;
  flowtable_main_t * fm = &flowtable_main;
  flowtable_per_session_t * fmt = &fm->per_session[0];
  upf_dpi_app_t *app = NULL;
  const char *app_name = NULL;
  const char *none = "None";
  upf_main_t * sm = &upf_main;

  if (dlist_is_empty(fmt->ht_lines, ht_line_head_index))
    return;

  ht_line = pool_elt_at_index(fmt->ht_lines, ht_line_head_index);
  index = ht_line->next;

  while (index != ht_line_head_index)
    {
      dlist_elt_t * e = pool_elt_at_index(fmt->ht_lines, index);
      flow = pool_elt_at_index(fm->flows, e->value);
      index = e->next;

      if (sm->upf_apps)
        app = pool_elt_at_index (sm->upf_apps, flow->app_index);

      app_name = (app != NULL) ? (const char*)app->name : none;

      vlib_cli_output (vm, "%llu: proto 0x%x, %U(%u) <-> %U(%u), packets %u, app %s, ttl %u",
                       flow->infos.data.flow_id,
                       flow->sig.s.ip4.proto,
                       format_ip4_address, &flow->sig.s.ip4.src,
                       ntohs(flow->sig.s.ip4.port_src),
                       format_ip4_address, &flow->sig.s.ip4.dst,
                       ntohs(flow->sig.s.ip4.port_dst),
                       flow->stats[0].pkts + flow->stats[1].pkts,
                       app_name,
                       flow->expire);
    }
}

static clib_error_t * upf_init (vlib_main_t * vm)
{
  upf_main_t * sm = &upf_main;
  char *argv[] = { "upf", "--no-huge", "--no-pci", NULL };
  clib_error_t * error;
  int ret;

  sm->vnet_main = vnet_get_main ();
  sm->vlib_main = vm;

  ret = rte_eal_init (3, argv);
  if (ret < 0)
    return clib_error_return (0, "rte_eal_init returned %d", ret);
  rte_log_set_global_level (RTE_LOG_DEBUG);

  if ((error = vlib_call_init_function (vm, upf_http_redirect_server_main_init)))
    return error;

  sm->nwi_index_by_name =
    hash_create_vec ( /* initial length */ 32, sizeof (u8), sizeof (uword));

  /* initialize the IP/TEID hash's */
  clib_bihash_init_8_8 (&sm->v4_tunnel_by_key,
			"upf_v4_tunnel_by_key", UPF_MAPPING_BUCKETS,
			UPF_MAPPING_MEMORY_SIZE);
  clib_bihash_init_24_8 (&sm->v6_tunnel_by_key,
			"upf_v6_tunnel_by_key", UPF_MAPPING_BUCKETS,
			UPF_MAPPING_MEMORY_SIZE);

  sm->peer_index_by_ip = hash_create_mem (0, sizeof (ip46_address_fib_t), sizeof (uword));

  sm->node_index_by_fqdn =
    hash_create_vec ( /* initial length */ 32, sizeof (u8), sizeof (uword));
  sm->node_index_by_ip = hash_create_mem (0, sizeof (ip46_address_t), sizeof (uword));

#if 0
  sm->vtep6 = hash_create_mem (0, sizeof (ip6_address_t), sizeof (uword));
#endif

  udp_register_dst_port (vm, UDP_DST_PORT_GTPU,
			 gtpu4_input_node.index, /* is_ip4 */ 1);
  udp_register_dst_port (vm, UDP_DST_PORT_GTPU6,
			 gtpu6_input_node.index, /* is_ip4 */ 0);

  sm->fib_node_type = fib_node_register_new_type (&upf_vft);

  sm->upf_app_by_name = hash_create_vec ( /* initial length */ 32,
                                      sizeof (u8), sizeof (uword));

  flowtable_init(vm);

  return sx_server_main_init(vm);
}

VLIB_INIT_FUNCTION (upf_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (upf, static) =
{
  .arc_name = "device-input",
  .node_name = "upf",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
