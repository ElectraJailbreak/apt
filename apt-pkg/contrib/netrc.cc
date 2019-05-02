// -*- mode: cpp; mode: fold -*-
// Description								/*{{{*/
/* ######################################################################

   netrc file parser - returns the login and password of a give host in
                       a specified netrc-type file

   Originally written by Daniel Stenberg, <daniel@haxx.se>, et al. and
   placed into the Public Domain, do with it what you will.

   ##################################################################### */
									/*}}}*/
#include <config.h>

#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/strutl.h>

#include <iostream>

#include "netrc.h"

/* Get user and password from .netrc when given a machine name */
bool MaybeAddAuth(FileFd &NetRCFile, URI &Uri)
{
   if (Uri.User.empty() == false || Uri.Password.empty() == false)
      return true;
   if (NetRCFile.IsOpen() == false || NetRCFile.Failed())
      return false;
   auto const Debug = _config->FindB("Debug::Acquire::netrc", false);

   std::string lookfor;
   if (Uri.Port != 0)
      strprintf(lookfor, "%s:%i%s", Uri.Host.c_str(), Uri.Port, Uri.Path.c_str());
   else
      lookfor.append(Uri.Host).append(Uri.Path);

   enum
   {
      NO,
      MACHINE,
      GOOD_MACHINE,
      LOGIN,
      PASSWORD
   } active_token = NO;
   std::string line;
   while (NetRCFile.Eof() == false || line.empty() == false)
   {
      if (line.empty())
      {
	 if (NetRCFile.ReadLine(line) == false)
	    break;
	 else if (line.empty())
	    continue;
      }
      auto tokenend = line.find_first_of("\t ");
      std::string token;
      if (tokenend != std::string::npos)
      {
	 token = line.substr(0, tokenend);
	 line.erase(0, tokenend + 1);
      }
      else
	 std::swap(line, token);
      if (token.empty())
	 continue;
      switch (active_token)
      {
      case NO:
	 if (token == "machine")
	    active_token = MACHINE;
	 break;
      case MACHINE:
	 if (token.find('/') == std::string::npos)
	 {
	    if (Uri.Port != 0 && Uri.Host == token)
	       active_token = GOOD_MACHINE;
	    else if (lookfor.compare(0, lookfor.length() - Uri.Path.length(), token) == 0)
	       active_token = GOOD_MACHINE;
	    else
	       active_token = NO;
	 }
	 else
	 {
	    if (APT::String::Startswith(lookfor, token))
	       active_token = GOOD_MACHINE;
	    else
	       active_token = NO;
	 }
	 break;
      case GOOD_MACHINE:
	 if (token == "login")
	    active_token = LOGIN;
	 else if (token == "password")
	    active_token = PASSWORD;
	 else if (token == "machine")
	 {
	    if (Debug)
	       std::clog << "MaybeAddAuth: Found matching host adding '" << Uri.User << "' and '" << Uri.Password << "' for "
			 << (std::string)Uri << " from " << NetRCFile.Name() << std::endl;
	    return true;
	 }
	 break;
      case LOGIN:
	 std::swap(Uri.User, token);
	 active_token = GOOD_MACHINE;
	 break;
      case PASSWORD:
	 std::swap(Uri.Password, token);
	 active_token = GOOD_MACHINE;
	 break;
      }
   }
   if (active_token == GOOD_MACHINE)
   {
      if (Debug)
	 std::clog << "MaybeAddAuth: Found matching host adding '" << Uri.User << "' and '" << Uri.Password << "' for "
		   << (std::string)Uri << " from " << NetRCFile.Name() << std::endl;
      return true;
   }
   else if (active_token == NO)
   {
      if (Debug)
	 std::clog << "MaybeAddAuth: Found no matching host for "
		   << (std::string)Uri << " from " << NetRCFile.Name() << std::endl;
      return true;
   }
   else if (Debug)
   {
      std::clog << "MaybeAddAuth: Found no matching host (syntax error: token:";
      switch (active_token)
      {
	 case NO: std::clog << "NO"; break;
	 case MACHINE: std::clog << "MACHINE"; break;
	 case GOOD_MACHINE: std::clog << "GOOD_MACHINE"; break;
	 case LOGIN: std::clog << "LOGIN"; break;
	 case PASSWORD: std::clog << "PASSWORD"; break;
      }
      std::clog << ") for " << (std::string)Uri << " from " << NetRCFile.Name() << std::endl;
   }
   return false;
}

void maybe_add_auth(URI &Uri, std::string NetRCFile)
{
   if (FileExists(NetRCFile) == false)
      return;
   FileFd fd;
   if (fd.Open(NetRCFile, FileFd::ReadOnly))
      MaybeAddAuth(fd, Uri);
}

/* Check if we are authorized. */
bool IsAuthorized(pkgCache::PkgFileIterator const I, std::vector<std::unique_ptr<FileFd>> &authconfs)
{
   if (authconfs.empty())
   {
      _error->PushToStack();
      auto const netrc = _config->FindFile("Dir::Etc::netrc");
      if (not netrc.empty())
      {
	 authconfs.emplace_back(new FileFd());
	 authconfs.back()->Open(netrc, FileFd::ReadOnly);
      }

      auto const netrcparts = _config->FindDir("Dir::Etc::netrcparts");
      if (not netrcparts.empty())
      {
	 for (auto const &netrc : GetListOfFilesInDir(netrcparts, "conf", true, true))
	 {
	    authconfs.emplace_back(new FileFd());
	    authconfs.back()->Open(netrc, FileFd::ReadOnly);
	 }
      }
      _error->RevertToStack();
   }

   // FIXME: Use the full base url
   URI uri(std::string("http://") + I.Site() + "/");
   for (auto &authconf : authconfs)
   {
      if (not authconf->IsOpen())
	 continue;
      if (not authconf->Seek(0))
	 continue;

      MaybeAddAuth(*authconf, uri);

      if (not uri.User.empty() || not uri.Password.empty())
	 return true;
   }

   return false;
}
