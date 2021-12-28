// Copyright (c) 2014-2018 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

/**
* @file utils.c
*
* @brief Common methods to read values from a file, evaluate sysfs path, etc
*
*/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <glib.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <nyx/module/nyx_log.h>
#include "msgid.h"

/**
 * Returns string in pre-allocated buffer.
 */

int FileGetString(const char *path, char *ret_string, size_t maxlen)
{
	GError *gerror = NULL;
	char *contents = NULL;
	gsize len;

	if (!path || !g_file_get_contents(path, &contents, &len, &gerror))
	{
		if (gerror)
		{
			nyx_error(MSGID_NYX_MOD_GET_STRING_ERR, 0, "error: %s", gerror->message);
			g_error_free(gerror);
		}

		return -1;
	}

	g_strstrip(contents);
	g_strlcpy(ret_string, contents, maxlen);
	g_free(contents);

	return 0;
}

int FileGetDouble(const char *path, double *ret_data)
{
	GError *gerror = NULL;
	char *contents = NULL;
	char *endptr;
	gsize len;
	float val;

	if (!path || !g_file_get_contents(path, &contents, &len, &gerror))
	{
		if (gerror)
		{
			nyx_error(MSGID_NYX_MOD_GET_DOUBLE_ERR, 0, "error: %s", gerror->message);
			g_error_free(gerror);
		}

		return -1;
	}

	val = strtod(contents, &endptr);

	if (endptr == contents)
	{
		nyx_error(MSGID_NYX_MOD_GET_STRTOD_ERR, 0, "Invalid input in %s.", path);
		goto end;
	}

	if (ret_data)
	{
		*ret_data = val;
	}

end:
	g_free(contents);
	return 0;
}

char *find_power_supply_sysfs_path(const char *device_type)
{
	GError *gerror = NULL;
	GDir *dir;
	GDir *subdir;
	gchar *dir_path = NULL;
	gchar *full_path = NULL;
	const char *sub_dir_name;
	const char *file_name;
	char file_contents[64];
	char base_dir[64] = "/sys/class/power_supply/";

	dir = g_dir_open(base_dir, 0, &gerror);

    nyx_warn(MSGID_NYX_MOD_TP_INVALID_EVENT, 0,"Herrie utils.c dir = **%s**", dir);
    nyx_warn(MSGID_NYX_MOD_TP_INVALID_EVENT, 0,"Herrie utils.c device_type = **%s**", device_type);

	if (gerror)
	{
		nyx_error(MSGID_NYX_MOD_SYSFS_ERR, 0, "error: %s", gerror->message);
		g_error_free(gerror);
		return NULL;
	}

	while ((sub_dir_name = g_dir_read_name(dir)) != 0)
	{
        nyx_warn(MSGID_NYX_MOD_TP_INVALID_EVENT, 0,"Herrie utils.c inside while sub_dir_name = **%c** ", sub_dir_name);
		// ignore hidden files
		if ('.' == sub_dir_name[0])
		{
			continue;
		}

		dir_path = g_build_filename(base_dir, sub_dir_name, NULL);
        nyx_warn(MSGID_NYX_MOD_TP_INVALID_EVENT, 0,"Herrie utils.c dir_path = **%s**", dir_path);

		if (g_file_test(dir_path, G_FILE_TEST_IS_DIR))
		{
            nyx_warn(MSGID_NYX_MOD_TP_INVALID_EVENT, 0,"Herrie utils.c inside if dir_path");
			subdir = g_dir_open(dir_path, 0, &gerror);

			if (gerror)
			{
				nyx_error(MSGID_NYX_MOD_GET_DIR_ERR, 0, "error: %s", gerror->message);
				g_error_free(gerror);
				return NULL;
			}

			while ((file_name = g_dir_read_name(subdir)) != 0)
			{
                //nyx_warn(MSGID_NYX_MOD_TP_INVALID_EVENT, 0,"Herrie utils.c inside while file_name = **%s** ", file_name);
				if (strcmp(file_name, "type") == 0)
				{
                    //nyx_warn(MSGID_NYX_MOD_TP_INVALID_EVENT, 0,"Herrie utils.c inside while file_name filename = type");
					full_path = g_build_filename(dir_path, file_name, NULL);
                    //nyx_warn(MSGID_NYX_MOD_TP_INVALID_EVENT, 0,"Herrie utils.c inside while full_path = %s", full_path);
					FileGetString(full_path, file_contents, 64);

                    //nyx_warn(MSGID_NYX_MOD_TP_INVALID_EVENT, 0,"Herrie utils.c inside while file_contents = **%s**", file_contents);

					if (strcmp(file_contents, device_type) == 0)
					{
                        nyx_warn(MSGID_NYX_MOD_TP_INVALID_EVENT, 0,"Herrie utils.c file_contents and device_type are equal");
                        //nyx_warn(MSGID_NYX_MOD_TP_INVALID_EVENT, 0,"Herrie utils.c file_contents and device_type are equal dir_path = %s", dir_path);
						return dir_path;
					}

					g_free(full_path);
					full_path = NULL;
				}
			}
		}

		g_free(dir_path);
		dir_path = NULL;
	}

	return NULL;
}
