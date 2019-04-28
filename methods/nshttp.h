// -*- mode: cpp; mode: fold -*-
// Description								/*{{{*/
/* ######################################################################

   HTTP method - Transfer files via rsh compatible program

   ##################################################################### */
									/*}}}*/
#ifndef APT_NSHTTP_H
#define APT_NSHTTP_H

#include <string>
#include <time.h>

#include <apt-pkg/strutl.h>
#include <Foundation/Foundation.h>

class Hashes;
class FileFd;

#include "aptmethod.h"

class HttpMethod : public aptMethod
{
   virtual bool Fetch(FetchItem *Itm) APT_OVERRIDE;
   virtual bool Configuration(std::string Message) APT_OVERRIDE;

   NSURLSession *session;

   static std::string FailFile;
   static int FailFd;
   static time_t FailTime;
   static APT_NORETURN void SigTerm(int);

   public:

   explicit HttpMethod(std::string &&Prog);
};

#endif
