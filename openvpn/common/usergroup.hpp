//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

#ifndef OPENVPN_COMMON_USERGROUP_H
#define OPENVPN_COMMON_USERGROUP_H

#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <sys/types.h>

#include <cstring>     // for std::strerror()

#include <string>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/format.hpp>

namespace openvpn {
  class SetUserGroup
  {
  public:
    OPENVPN_EXCEPTION(user_group_err);

    SetUserGroup(const char *user, const char *group)
      : pw(NULL),
	gr(NULL)
    {
      if (user)
	{
	  pw = getpwnam(user);
	  if (!pw)
	    OPENVPN_THROW(user_group_err, "user lookup failed for '" << user << '\'');
	  user_name = user;
	}
      if (group)
	{
	  gr = getgrnam(group);
	  if (!gr)
	    OPENVPN_THROW(user_group_err, "group lookup failed for '" << group << '\'');
	  group_name = group;
	}
    }

    void activate() const
    {
      if (gr)
	{
	  if (setgid(gr->gr_gid))
	    OPENVPN_THROW(user_group_err, "setgid failed for group '" << group_name << "': " << std::strerror(errno));
	  gid_t gr_list[1];
	  gr_list[0] = gr->gr_gid;
	  if (setgroups(1, gr_list))
	    OPENVPN_THROW(user_group_err, "setgroups failed for group '" << group_name << "': " << std::strerror(errno));
	  OPENVPN_LOG("GID set to '" << group_name << '\'');
	}
      if (pw)
	{
	  if (setuid(pw->pw_uid))
	    OPENVPN_THROW(user_group_err, "setuid failed for user '" << user_name << "': " << std::strerror(errno));
	  OPENVPN_LOG("UID set to '" << user_name << '\'');
	}
    }

  private:
    std::string user_name;
    std::string group_name;

    struct passwd *pw;
    struct group *gr;
  };
}

#endif