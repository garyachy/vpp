/*
 * dpi.h - 3GPP TS 29.244 UPF DPI header file
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
#ifndef __included_upf_dpi_h__
#define __included_upf_dpi_h__

typedef struct {
  /* App index */
  u32 index;
  /* Regex expression */
  u8 *rule;
} upf_dpi_args_t;

int upf_dpi_add_multi_regex(upf_dpi_args_t * args, u32 * db_index, u8 create);
int upf_dpi_lookup(u32 db_index, u8 * str, uint16_t length, u32 * app_index);
int upf_dpi_remove(u32 db_index);

#endif /* __included_upf_dpi_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
