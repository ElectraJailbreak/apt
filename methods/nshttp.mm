// -*- mode: cpp; mode: fold -*-
// Description								/*{{{*/
/* ######################################################################

   RSH method - Transfer files via rsh compatible program

   Written by Ben Collins <bcollins@debian.org>, Copyright (c) 2000
   Licensed under the GNU General Public License v2 [no exception clauses]

   ##################################################################### */
									/*}}}*/
// Include Files							/*{{{*/
#include <config.h>

#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/hashes.h>
#include <apt-pkg/strutl.h>

#include "nshttp.h"
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <apti18n.h>

unsigned long TimeOut = 30;
Configuration::Item const *HttpOptions = 0;
time_t HttpMethod::FailTime = 0;

// HttpMethod::HttpMethod - Constructor					/*{{{*/
HttpMethod::HttpMethod(std::string &&pProg) : aptMethod(std::move(pProg),"1.0",SendConfig)
{
   signal(SIGTERM,SigTerm);
   signal(SIGINT,SigTerm);
}
									/*}}}*/
// HttpMethod::Configuration - Handle a configuration message		/*{{{*/
// ---------------------------------------------------------------------
bool HttpMethod::Configuration(std::string Message)
{
   // enabling privilege dropping for this method requires configuration…
   // … which is otherwise lifted straight from root, so use it by default.
   _config->Set(std::string("Binary::") + Binary + "::APT::Sandbox::User", "");

   if (aptMethod::Configuration(Message) == false)
      return false;

   std::string const timeconf = std::string("Acquire::") + Binary + "::Timeout";
   TimeOut = _config->FindI(timeconf, TimeOut);
   std::string const optsconf = std::string("Acquire::") + Binary + "::Options";
   HttpOptions = _config->Tree(optsconf.c_str());

   return true;
}
									/*}}}*/
// HttpMethod::SigTerm - Clean up and timestamp the files on exit	/*{{{*/
// ---------------------------------------------------------------------
/* */
void HttpMethod::SigTerm(int)
{
   _exit(100);
}
									/*}}}*/
// HttpMethod::Fetch - Fetch a URI					/*{{{*/
// ---------------------------------------------------------------------
/* */
bool HttpMethod::Fetch(FetchItem *Itm)
{
   URI Get = Itm->Uri;
   std::string cppGet = Get;
   NSURL *URL = [NSURL URLWithString:[NSString stringWithUTF8String:cppGet.c_str()]];
   __block FetchResult Res;
   Res.Filename = Itm->DestFile;
   Res.IMSHit = false;

   __block BOOL success = NO;

   dispatch_semaphore_t sem = dispatch_semaphore_create(0);

   NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:URL cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData timeoutInterval:TimeOut];
   [request setHTTPMethod:@"HEAD"];
   [[[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *, NSURLResponse *response, NSError *error){
      NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
      if (httpResponse.statusCode >= 200){
         if (httpResponse.expectedContentLength != NSURLResponseUnknownLength)
            Res.Size = httpResponse.expectedContentLength;
         NSString *dateModified = httpResponse.allHeaderFields[@"Date"];
         if (dateModified){
            NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
            [formatter setLocale:[NSLocale localeWithLocaleIdentifier:@"en"]];
            [formatter setDateFormat:@"EEEE, dd LLL yyyy HH:mm:ss zzz"];
            NSDate *date = [formatter dateFromString:dateModified];
            this->FailTime = [date timeIntervalSince1970];
            [formatter release];
         }
         success = YES;
      } else {
         success = NO;
      }
      dispatch_semaphore_signal(sem);
   }] resume];

   Status(_("Connecting to %s"), Get.Host.c_str());
   dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, TimeOut * NSEC_PER_SEC));

   // Get the files information
   if (!success)
   {
      return false;
   }

   // See if it is an IMS hit
   if (Itm->LastModified == FailTime) {
      Res.Size = 0;
      Res.IMSHit = true;
      URIDone(Res);
      return true;
   }

   // See if the file exists
   struct stat Buf;
   if (stat(Itm->DestFile.c_str(),&Buf) == 0) {
      if (Res.Size == (unsigned long long)Buf.st_size && FailTime == Buf.st_mtime) {
         Res.Size = Buf.st_size;
         Res.LastModified = Buf.st_mtime;
         Res.ResumePoint = Buf.st_size;
         URIDone(Res);
         return true;
      }

      // Resume?
      if (FailTime == Buf.st_mtime && Res.Size > (unsigned long long)Buf.st_size)
         Res.ResumePoint = Buf.st_size;
   }

   // Open the file
   Hashes Hash(Itm->ExpectedHashes);
   {
      [request setHTTPMethod:@"GET"];

      success = NO;

      NSURLSessionDownloadTask *task = [[NSURLSession sharedSession] downloadTaskWithRequest:request completionHandler:^(NSURL *location, NSURLResponse *response, NSError *error){
         NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
         if (httpResponse.statusCode == 200 && !error){
            NSString *destFile = [NSString stringWithUTF8String:Itm->DestFile.c_str()];
            [[NSFileManager defaultManager] removeItemAtPath:destFile error:nil];
            success = [[NSFileManager defaultManager] moveItemAtPath:location.path toPath:destFile error:&error];
            if (error){
               success = NO;
            }
         }
         dispatch_semaphore_signal(sem);
      }];
      [task resume];
      dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, TimeOut * NSEC_PER_SEC));

      if (!success){
         Fail(true);
         return true;
      }

      FileFd Fd(Itm->DestFile,FileFd::WriteExists);
      Hash.AddFD(Fd,Hashes::UntilEOF);

      URIStart(Res);

      Res.Size = Fd.Size();
      struct timeval times[2];
      times[0].tv_sec = FailTime;
      times[1].tv_sec = FailTime;
      times[0].tv_usec = times[1].tv_usec = 0;
      utimes(Fd.Name().c_str(), times);
   }

   Res.LastModified = FailTime;
   Res.TakeHashes(Hash);

   URIDone(Res);

   return true;
}
									/*}}}*/

int main(int, const char *argv[])
{
   return HttpMethod(flNotDir(argv[0])).Run();
}
