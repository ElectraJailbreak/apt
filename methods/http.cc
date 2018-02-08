// -*- mode: cpp; mode: fold -*-
// Description                      /*{{{*/
// $Id: http.cc,v 1.59 2004/05/08 19:42:35 mdz Exp $
/* ######################################################################

   HTTP Acquire Method - This is the HTTP acquire method for APT.
   
   It uses HTTP/1.1 and many of the fancy options there-in, such as
   pipelining, range, if-range and so on. 

   It is based on a doubly buffered select loop. A groupe of requests are 
   fed into a single output buffer that is constantly fed out the 
   socket. This provides ideal pipelining as in many cases all of the
   requests will fit into a single packet. The input socket is buffered 
   the same way and fed into the fd for the file (may be a pipe in future).
   
   This double buffering provides fairly substantial transfer rates,
   compared to wget the http method is about 4% faster. Most importantly,
   when HTTP is compared with FTP as a protocol the speed difference is
   huge. In tests over the internet from two sites to llug (via ATM) this
   program got 230k/s sustained http transfer rates. FTP on the other 
   hand topped out at 170k/s. That combined with the time to setup the
   FTP connection makes HTTP a vastly superior protocol.
      
   ##################################################################### */
                           /*}}}*/
// Include Files                    /*{{{*/
// #include <config.h>

#include <apt-pkg/fileutl.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/hashes.h>
#include <apt-pkg/netrc.h>
#include <apt-pkg/strutl.h>
#include <apt-pkg/proxy.h>

#include <stddef.h>
#include <stdlib.h>
#include <sys/select.h>
#include <cstring>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <iostream>
#include <sstream>

#include "config.h"
#include "connect.h"
#include "http.h"

// #include <apti18n.h>

#include <netdb.h>
#include <dlfcn.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
extern "C" CFDictionaryRef SCDynamicStoreCopyProxies(void *);
                           /*}}}*/
using namespace std;

#define _(str) str

CFStringRef Firmware_;
const char *Machine_;
CFStringRef UniqueID_;

void CfrsError(const char *name, CFReadStreamRef rs) {
   CFStreamError se = CFReadStreamGetError(rs);

   if (se.domain == kCFStreamErrorDomainCustom) {
   } else if (se.domain == kCFStreamErrorDomainPOSIX) {
      _error->Error("POSIX: %s", strerror(se.error));
   } else if (se.domain == kCFStreamErrorDomainMacOSStatus) {
      _error->Error("MacOSStatus: %d", (int)se.error);
   } else if (se.domain == kCFStreamErrorDomainNetDB) {
      _error->Error("NetDB: %s %s", name, gai_strerror(se.error));
   } else if (se.domain == kCFStreamErrorDomainMach) {
      _error->Error("Mach: %d", (int)se.error);
   } else if (se.domain == kCFStreamErrorDomainHTTP) {
      switch (se.error) {
         case kCFStreamErrorHTTPParseFailure:
            _error->Error("Parse failure");
         break;

         case kCFStreamErrorHTTPRedirectionLoop:
            _error->Error("Redirection loop");
         break;

         case kCFStreamErrorHTTPBadURL:
            _error->Error("Bad URL");
         break;

         default:
            _error->Error("Unknown HTTP error: %d", (int)se.error);
         break;
      }
   } else if (se.domain == kCFStreamErrorDomainSOCKS) {
      _error->Error("SOCKS: %d", (int)se.error);
   } else if (se.domain == kCFStreamErrorDomainSystemConfiguration) {
      _error->Error("SystemConfiguration: %d", (int)se.error);
   } else if (se.domain == kCFStreamErrorDomainSSL) {
      _error->Error("SSL: %d", (int)se.error);
   } else {
      _error->Error("Domain #%d: %d", (int)se.domain, (int)se.error);
   }
}

unsigned long TimeOut = 120;

static const CFOptionFlags kNetworkEvents =
   kCFStreamEventOpenCompleted |
   kCFStreamEventHasBytesAvailable |
   kCFStreamEventEndEncountered |
   kCFStreamEventErrorOccurred |
0;

static void CFReadStreamCallback(CFReadStreamRef stream, CFStreamEventType event, void *arg) {
   switch (event) {
      case kCFStreamEventOpenCompleted:
      break;

      case kCFStreamEventHasBytesAvailable:
      case kCFStreamEventEndEncountered:
         *reinterpret_cast<int *>(arg) = 1;
         CFRunLoopStop(CFRunLoopGetCurrent());
      break;

      case kCFStreamEventErrorOccurred:
         *reinterpret_cast<int *>(arg) = -1;
         CFRunLoopStop(CFRunLoopGetCurrent());
      break;
   }
}

/* http://lists.apple.com/archives/Macnetworkprog/2006/Apr/msg00014.html */
int CFReadStreamOpen(CFReadStreamRef stream, double timeout) {
   CFStreamClientContext context;
   int value(0);

   memset(&context, 0, sizeof(context));
   context.info = &value;

   if (CFReadStreamSetClient(stream, kNetworkEvents, CFReadStreamCallback, &context)) {
      CFReadStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
      if (CFReadStreamOpen(stream))
         CFRunLoopRunInMode(kCFRunLoopDefaultMode, timeout, false);
      else
         value = -1;
      CFReadStreamSetClient(stream, kCFStreamEventNone, NULL, NULL);
   }

   return value;
}

// HttpMethod::SendReq - Send the HTTP request           /*{{{*/
// ---------------------------------------------------------------------
/* This places the http request in the outbound buffer */
void HttpMethod::SendReq(FetchItem *Itm)
{
}
                           /*}}}*/
std::unique_ptr<ServerState> HttpMethod::CreateServerState(URI const &uri)/*{{{*/
{
   return NULL;
}
                           /*}}}*/
void HttpMethod::RotateDNS()                 /*{{{*/
{
}
                           /*}}}*/
BaseHttpMethod::DealWithHeadersResult HttpMethod::DealWithHeaders(FetchResult &Res, RequestState &Req)/*{{{*/
{
   auto ret = BaseHttpMethod::DealWithHeaders(Res, Req);
   if (ret != BaseHttpMethod::FILE_IS_OPEN)
      return ret;
   if (Req.File.Open(Queue->DestFile, FileFd::WriteAny) == false)
      return ERROR_NOT_FROM_SERVER;

   FailFile = Queue->DestFile;
   FailFile.c_str();   // Make sure we don't do a malloc in the signal handler
   FailFd = Req.File.Fd();
   FailTime = Req.Date;

   if (Server->InitHashes(Queue->ExpectedHashes) == false || Req.AddPartialFileToHashes(Req.File) == false)
   {
      _error->Errno("read",_("Problem hashing file"));
      return ERROR_NOT_FROM_SERVER;
   }
   if (Req.StartPos > 0)
      Res.ResumePoint = Req.StartPos;

   SetNonBlock(Req.File.Fd(),true);
   return FILE_IS_OPEN;
}

// HttpMethod::Loop - Main loop              /*{{{*/
int HttpMethod::Loop()
{
   signal(SIGTERM,SigTerm);
   signal(SIGINT,SigTerm);
   
   Server = 0;

   std::set<std::string> cached;
   
   int FailCounter = 0;
   while (1)
   {      
      // We have no commands, wait for some to arrive
      if (Queue == 0)
      {
    if (WaitFd(STDIN_FILENO) == false)
       return 0;
      }
      
      /* Run messages, we can accept 0 (no message) if we didn't
         do a WaitFd above.. Otherwise the FD is closed. */
      int Result = Run(true);
      if (Result != -1 && (Result != 0 || Queue == 0))
      {
    if(FailReason.empty() == false ||
       ConfigFindB("DependOnSTDIN", true) == true)
       return 100;
    else
       return 0;
      }

      if (Queue == 0)
    continue;

      CFStringEncoding se = kCFStringEncodingUTF8;

      URI uri2 = Queue->Uri;
      string uriString = static_cast<string>(uri2);
    
      char *url = strdup(uriString.c_str());
    url:
      URI uri = std::string(url);
      std::string hs = uri.Host;

      if (cached.find(hs) != cached.end()) {
         _error->Error("Cached Failure");
         Fail(true);
         free(url);
         FailCounter = 0;
         continue;
      }

      std::string urs = uri;

      for (;;) {
         size_t bad = urs.find_first_of("+");
         if (bad == std::string::npos)
            break;
         // XXX: generalize
         urs = urs.substr(0, bad) + "%2b" + urs.substr(bad + 1);
      }

      CFStringRef sr = CFStringCreateWithCString(kCFAllocatorDefault, urs.c_str(), se);
      CFURLRef ur = CFURLCreateWithString(kCFAllocatorDefault, sr, NULL);
      CFRelease(sr);
      CFHTTPMessageRef hm = CFHTTPMessageCreateRequest(kCFAllocatorDefault, CFSTR("GET"), ur, kCFHTTPVersion1_1);
      CFRelease(ur);

      struct stat SBuf;
      if (stat(Queue->DestFile.c_str(), &SBuf) >= 0 && SBuf.st_size > 0) {
         sr = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("bytes=%li-"), (long) SBuf.st_size - 1);
         CFHTTPMessageSetHeaderFieldValue(hm, CFSTR("Range"), sr);
         CFRelease(sr);

         sr = CFStringCreateWithCString(kCFAllocatorDefault, TimeRFC1123(SBuf.st_mtime, false).c_str(), se);
         CFHTTPMessageSetHeaderFieldValue(hm, CFSTR("If-Range"), sr);
         CFRelease(sr);

         CFHTTPMessageSetHeaderFieldValue(hm, CFSTR("Cache-Control"), CFSTR("no-cache"));
      } else if (Queue->LastModified != 0) {
         sr = CFStringCreateWithCString(kCFAllocatorDefault, TimeRFC1123(Queue->LastModified, true).c_str(), se);
         CFHTTPMessageSetHeaderFieldValue(hm, CFSTR("If-Modified-Since"), sr);
         CFRelease(sr);

         CFHTTPMessageSetHeaderFieldValue(hm, CFSTR("Cache-Control"), CFSTR("no-cache"));
      } else
         CFHTTPMessageSetHeaderFieldValue(hm, CFSTR("Cache-Control"), CFSTR("max-age=0"));

      if (Firmware_ != NULL)
         CFHTTPMessageSetHeaderFieldValue(hm, CFSTR("X-Firmware"), Firmware_);

      sr = CFStringCreateWithCString(kCFAllocatorDefault, Machine_, se);
      CFHTTPMessageSetHeaderFieldValue(hm, CFSTR("X-Machine"), sr);
      CFRelease(sr);

      if (UniqueID_ != NULL)
         CFHTTPMessageSetHeaderFieldValue(hm, CFSTR("X-Unique-ID"), UniqueID_);

      CFHTTPMessageSetHeaderFieldValue(hm, CFSTR("User-Agent"), CFSTR("Telesphoreo APT-HTTP/1.0.592"));

      CFReadStreamRef rs = CFReadStreamCreateForHTTPRequest(kCFAllocatorDefault, hm);
      CFRelease(hm);

#define _kCFStreamPropertyReadTimeout CFSTR("_kCFStreamPropertyReadTimeout")
#define _kCFStreamPropertyWriteTimeout CFSTR("_kCFStreamPropertyWriteTimeout")
#define _kCFStreamPropertySocketImmediateBufferTimeOut CFSTR("_kCFStreamPropertySocketImmediateBufferTimeOut")

      /*SInt32 to(TimeOut);
      CFNumberRef nm(CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &to));os_log(OS_LOG_DEFAULT, "[%{public}s:%{public}d]",__BASE_FILE__,__LINE__);*/
      double to = TimeOut;
      CFNumberRef nm(CFNumberCreate(kCFAllocatorDefault, kCFNumberDoubleType, &to));

      CFReadStreamSetProperty(rs, _kCFStreamPropertyReadTimeout, nm);
      CFReadStreamSetProperty(rs, _kCFStreamPropertyWriteTimeout, nm);
      CFReadStreamSetProperty(rs, _kCFStreamPropertySocketImmediateBufferTimeOut, nm);
      CFRelease(nm);

      CFDictionaryRef dr = SCDynamicStoreCopyProxies(NULL);
      CFReadStreamSetProperty(rs, kCFStreamPropertyHTTPProxy, dr);
      CFRelease(dr);

      //CFReadStreamSetProperty(rs, kCFStreamPropertyHTTPShouldAutoredirect, kCFBooleanTrue);
      CFReadStreamSetProperty(rs, kCFStreamPropertyHTTPAttemptPersistentConnection, kCFBooleanTrue);

      FetchResult Res;
      CFIndex rd;
      UInt32 sc;

      uint8_t data[10240];
      size_t offset = 0;

      Status("Connecting to %s", hs.c_str());

      switch (CFReadStreamOpen(rs, to)) {
         case -1:
            CfrsError("Open", rs);
         goto fail;

         case 0:
            _error->Error("Host Unreachable");
            cached.insert(hs);
         goto fail;

         case 1:
            /* success */
         break;

         fail:
            Fail(true);
         goto done;
      }

      rd = CFReadStreamRead(rs, data, sizeof(data));

      if (rd == -1) {
         CfrsError(uri.Host.c_str(), rs);
         cached.insert(hs);
         Fail(true);
         goto done;
      }

      Res.Filename = Queue->DestFile;

      hm = (CFHTTPMessageRef) CFReadStreamCopyProperty(rs, kCFStreamPropertyHTTPResponseHeader);
      sc = CFHTTPMessageGetResponseStatusCode(hm);

      if (sc == 301 || sc == 302) {
         sr = CFHTTPMessageCopyHeaderFieldValue(hm, CFSTR("Location"));
         if (sr == NULL) {
            Fail();
            goto done_;
         } else {
            size_t ln = CFStringGetLength(sr) + 1;
            free(url);
            url = static_cast<char *>(malloc(ln));

            if (!CFStringGetCString(sr, url, ln, se)) {
               Fail();
               goto done_;
            }

            CFRelease(sr);
            goto url;
         }
      }

      sr = CFHTTPMessageCopyHeaderFieldValue(hm, CFSTR("Content-Range"));
      if (sr != NULL) {
         size_t ln = CFStringGetLength(sr) + 1;
         char cr[ln];

         if (!CFStringGetCString(sr, cr, ln, se)) {
            Fail();
            goto done_;
         }

         CFRelease(sr);

         if (sscanf(cr, "bytes %lu-%*u/%llu", &offset, &Res.Size) != 2) {
       _error->Error(_("The HTTP server sent an invalid Content-Range header"));
            Fail();
            goto done_;
         }

         if (offset > Res.Size) {
       _error->Error(_("This HTTP server has broken range support"));
            Fail();
            goto done_;
         }
      } else {
         sr = CFHTTPMessageCopyHeaderFieldValue(hm, CFSTR("Content-Length"));
         if (sr != NULL) {
            Res.Size = CFStringGetIntValue(sr);
            CFRelease(sr);
         }
      }

      time(&Res.LastModified);

      sr = CFHTTPMessageCopyHeaderFieldValue(hm, CFSTR("Last-Modified"));
      if (sr != NULL) {
         size_t ln = CFStringGetLength(sr) + 1;
         char cr[ln];

         if (!CFStringGetCString(sr, cr, ln, se)) {
            Fail();
            goto done_;
         }

         CFRelease(sr);

         if (!RFC1123StrToTime(cr, Res.LastModified)) {
       _error->Error(_("Unknown date format"));
            Fail();
            goto done_;
         }
      }

      if (sc < 200 || (sc >= 300 && sc != 304)) {
         sr = CFHTTPMessageCopyResponseStatusLine(hm);

         size_t ln = CFStringGetLength(sr) + 1;
         char cr[ln];

         if (!CFStringGetCString(sr, cr, ln, se)) {
            Fail();
            goto done;
         }

         CFRelease(sr);

         _error->Error("%s", cr);

         Fail();
         goto done_;
      }

      CFRelease(hm);

      if (sc == 304) {
         unlink(Queue->DestFile.c_str());
         Res.IMSHit = true;
         Res.LastModified = Queue->LastModified;
         URIDone(Res);
      } else {
         Hashes hash;

         File = new FileFd(Queue->DestFile, FileFd::WriteAny);
         if (_error->PendingError() == true) {
            delete File;
            File = NULL;
            Fail();
            goto done;
         }

         FailFile = Queue->DestFile;
         FailFile.c_str();   // Make sure we dont do a malloc in the signal handler
         FailFd = File->Fd();
         FailTime = Res.LastModified;

         Res.ResumePoint = offset;
         ftruncate(File->Fd(), offset);

         if (offset != 0) {
            lseek(File->Fd(), 0, SEEK_SET);
            if (!hash.AddFD(File->Fd(), offset)) {
               _error->Errno("read", _("Problem hashing file"));
               delete File;
               File = NULL;
               Fail();
               goto done;
            }
         }

         lseek(File->Fd(), 0, SEEK_END);

         URIStart(Res);

         read: if (rd == -1) {
            CfrsError("rd", rs);
            Fail(true);
         } else if (rd == 0) {
            if (Res.Size == 0)
               Res.Size = File->Size();
       
            // Timestamp
            struct timeval times[2];
            times[0].tv_sec = times[1].tv_sec = Res.LastModified;
            times[0].tv_usec = times[1].tv_usec = 0;
            utimes(Queue->DestFile.c_str(), times);

            Res.TakeHashes(hash);
            URIDone(Res);
         } else {
            hash.Add(data, rd);

            uint8_t *dt = data;
            while (rd != 0) {
               int sz = write(File->Fd(), dt, rd);

               if (sz == -1) {
                  delete File;
                  File = NULL;
                  Fail();
                  goto done;
               }

               dt += sz;
               rd -= sz;
            }

            rd = CFReadStreamRead(rs, data, sizeof(data));
            goto read;
         }
      }

      goto done;

   done_:
      CFRelease(hm);
   done:
      CFReadStreamClose(rs);
      CFRelease(rs);
      free(url);

      FailCounter = 0;
   }
   
   return 0;
}
HttpMethod::HttpMethod(std::string &&pProg) : BaseHttpMethod(pProg.c_str(), "1.2", Pipeline | SendConfig)/*{{{*/
{
   auto addName = std::inserter(methodNames, methodNames.begin());
   if (Binary != "http")
      addName = "http";
   auto const plus = Binary.find('+');
   if (plus != std::string::npos)
      addName = Binary.substr(0, plus);
   File = 0;
   Server = 0;
}
                           /*}}}*/

int main(int, const char *argv[])
{
   // ignore SIGPIPE, this can happen on write() if the socket
   // closes the connection (this is dealt with via ServerDie())
   signal(SIGPIPE, SIG_IGN);

   size_t size;
   sysctlbyname("hw.machine", NULL, &size, NULL, 0);
   char *machine = new char[size];
   sysctlbyname("hw.machine", machine, &size, NULL, 0);
   Machine_ = machine;

   const char *path = "/System/Library/CoreServices/SystemVersion.plist";
   CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (uint8_t *) path, strlen(path), false);

   CFPropertyListRef plist; {
      CFReadStreamRef stream = CFReadStreamCreateWithFile(kCFAllocatorDefault, url);
      CFReadStreamOpen(stream);
      plist = CFPropertyListCreateFromStream(kCFAllocatorDefault, stream, 0, kCFPropertyListImmutable, NULL, NULL);
      CFReadStreamClose(stream);
   }

   CFRelease(url);

   if (plist != NULL) {
      Firmware_ = (CFStringRef) CFRetain(CFDictionaryGetValue((CFDictionaryRef) plist, CFSTR("ProductVersion")));
      CFRelease(plist);
   }

   if (UniqueID_ == NULL)
   if (void *libMobileGestalt = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_GLOBAL | RTLD_LAZY))
   if (CFStringRef (*$MGCopyAnswer)(CFStringRef) = (CFStringRef (*)(CFStringRef)) dlsym(libMobileGestalt, "MGCopyAnswer"))
      UniqueID_ = $MGCopyAnswer(CFSTR("UniqueDeviceID"));

   std::string Binary = flNotDir(argv[0]);
   if (Binary.find('+') == std::string::npos && Binary != "http")
      Binary.append("+http");
   return HttpMethod(std::move(Binary)).Loop();
}