//----------------------------------------------------------------------------

#include "crsUtils.hpp"
#include <regex>

#if defined _WIN32
# include <Dbghelp.h>
#else
# include <execinfo.h>
#endif

#if defined __APPLE__
# include <libproc.h>
#endif

namespace crs {

#define THROW_SYSTEM_FAILURE(errorCode)                              \
        do                                                           \
        {                                                            \
          std::string msg{strerror((errorCode))};                    \
          throw std::runtime_error{txt("%:%:%() failure --- %\n%",   \
                                       __FILE__, __LINE__, __func__, \
                                       msg, computeStackTrace())};   \
        } while(0)

#define THROW_NOT_AVAILABLE(msg)                                     \
        do                                                           \
        {                                                            \
          throw std::runtime_error{txt("%:%:%() not available%\n%",  \
                                       __FILE__, __LINE__, __func__, \
                                       msg, computeStackTrace())};   \
        } while(0)

#define SSL_ERROR_MSG(fnct) \
        (txt("%: %", #fnct, ::ERR_error_string(::ERR_get_error(), nullptr)))

#define THROW_SSL_ERROR(fnct)                                        \
        do                                                           \
        {                                                            \
          throw std::runtime_error{txt("%:%:%() %\n%",               \
                                       __FILE__, __LINE__, __func__, \
                                       SSL_ERROR_MSG(fnct),          \
                                       computeStackTrace())};        \
        } while(0)

#if !defined _WIN32
  static std::map<int, std::function<void(int)>> sigaction_data_{};
  static std::atomic_flag sigaction_lock_=ATOMIC_FLAG_INIT;
  static std::vector<std::mutex> ssl_locks_;
#endif

[[maybe_unused]] static bool staticInitialisation_=([]()
  {
#if defined _WIN32
    ::SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOOPENFILEERRORBOX);
    ::_setmode(STDIN_FILENO, _O_BINARY);
    ::_setmode(STDOUT_FILENO, _O_BINARY);
    ::_setmode(STDERR_FILENO, _O_BINARY);
    WSADATA wsaData;
    ::WSAStartup(MAKEWORD(2,2),&wsaData);
#endif
#if defined _MSC_VER // MSVC++ does not show anything
    std::set_terminate([]()
      {
        err("Uncaught exception!\n");
        // FIXME: fails in MSVC++
        // try { throw; }
        // catch(const std::exception &e) { err("%\n",e.what()); }
        std::abort();
      });
#endif
#if !defined _WIN32
    sigaction(SIGPIPE, [](int){}); // avoid spurious termination on IO failure
#endif
    return true;
  })();

template<typename Dst,
         typename WriteFnct>
inline
int // written bytes (contentSize expected)
writeAll_(Dst dst,
          const void *content,
          int contentSize,
          WriteFnct writeFnct)
{
  auto ptr{reinterpret_cast<const char *>(content)};
  int remaining{contentSize};
  while(remaining)
  {
    int r{writeFnct(dst, ptr, remaining)};
    if(!r)
    {
      break; // EOF
    }
    ptr+=r;
    remaining-=r;
  }
  return contentSize-remaining;
}

template<typename Dst,
         typename WriteAllFnct>
inline
int // written bytes (len(msg) expected)
writeAll_(Dst dst,
          const std::string &msg,
          WriteAllFnct writeAllFnct)
{
  return writeAllFnct(dst, data(msg), len(msg));
}

template<typename Src,
         typename ReadFnct>
inline
int // read bytes (bufferCapacity expected) or 0 (EOF)
readAll_(Src src,
         void *buffer,
         int bufferCapacity,
         ReadFnct readFnct)
{
  auto ptr{reinterpret_cast<char *>(buffer)};
  int remaining{bufferCapacity};
  while(remaining)
  {
    int r{readFnct(src, ptr, remaining)};
    if(!r)
    {
      break; // EOF
    }
    ptr+=r;
    remaining-=r;
  }
  return bufferCapacity-remaining;
}

template<typename Src,
         typename ReadFnct>
inline
std::string // read text or "" (EOF)
read_(Src src,
      int capacity,
      ReadFnct readFnct)
{
  std::string result;
  uninitialised_resize(result, capacity);
  result.resize(readFnct(src, data(result), capacity));
  return result;
}

template<typename Src,
         typename ReadAllFnct>
inline
std::string // read text or "" (EOF)
readAll_(Src src,
         int capacity,
         ReadAllFnct readAllFnct)
{
  std::string result;
  uninitialised_resize(result, capacity);
  result.resize(readAllFnct(src, data(result), capacity));
  return result;
}

template<typename Src,
         typename ReadFnct>
inline
std::string // read text line or "" (EOF)
readLine_(Src src,
          ReadFnct readFnct)
{
  std::string result;
  char c;
  while(readFnct(src, &c, 1)==1)
  {
    result+=c;
    if(c=='\n')
    {
      break; // end of line
    }
  }
  return result;
}

//----------------------------------------------------------------------------

std::tuple<std::string, // protocol
           std::string, // hostname
           uint16_t,    // port number
           std::string, // resource
           std::string> // params
parseUriWithParams(const std::string &uri)
{
  std::string protocol;
  std::string hostname;
  uint16_t portNumber=0;
  std::string resource;
  std::string params;
  //              1                2       3 4         5      6   7
  std::regex re("^([a-zA-Z0-9]+)://([^:/]+)(:([0-9]+))?([^?]*)([?](.*))?$",
                std::regex::extended);
  std::smatch m;
  if(std::regex_search(uri, m, re))
  {
    protocol=m.str(1);
    portNumber=protocol=="http" ? 80 :
               protocol=="https" ? 443 : 0;
    if((m[3].matched&&(extract(m.str(4), portNumber)!=1))||!portNumber)
    {
      protocol.clear();
      portNumber=0;
    }
    else
    {
      hostname=m.str(2);
      resource=m.str(5);
      if(empty(resource))
      {
        resource="/";
      }
      if(m[6].matched)
      {
        params=m.str(7);
      }
    }
  }
  return {std::move(protocol),
          std::move(hostname),
          std::move(portNumber),
          std::move(resource),
          std::move(params)};
}

std::tuple<std::string, // protocol
           std::string, // hostname
           uint16_t,    // port number
           std::string> // resource
parseUri(const std::string &uri)
{
  auto [protocol, hostname, portNumber,
        resource, params]=parseUriWithParams(uri);
  if(!empty(params))
  {
    resource+="?"+params;
  }
  return {std::move(protocol),
          std::move(hostname),
          std::move(portNumber),
          std::move(resource)};
}

std::tuple<std::string, // protocol
           std::string, // hostname
           uint16_t>    // port number
parseProxyUri(const std::string &uri)
{
  auto [protocol, hostname, portNumber, resource]=parseUri(uri);
  if((resource!="/")&&!empty(resource))
  {
    protocol.clear();
    hostname.clear();
    portNumber=0;
  }
  return {std::move(protocol),
          std::move(hostname),
          std::move(portNumber)};
}

double // energy consumed by CPU, in Joules
cpuEnergy()
{
  static bool available=true;
  static std::vector<int> energyFd; // FIXME: not closed on exit
  static std::vector<int64_t> maxRange;
  static std::vector<int64_t> initValue;
  if(!available)
  {
    return 0.0;
  }
  char buffer[0x100];
  auto readValue=[&buffer](const auto &fd)
    {
      int r=read(fd, buffer, sizeof(buffer))-1; // ignore trailing \n
      int64_t value=0;
      for(int i=0; i<r; ++i)
      {
        value=value*10+(buffer[i]-'0');
      }
      return value;
    };
  if(empty(energyFd))
  {
    for(int cpu=0; ; ++cpu)
    {
      const auto dir=txt("/sys/class/powercap/intel-rapl/intel-rapl:%", cpu);
      const auto maxRangeFile=dir+"/max_energy_range_uj";
      const auto energyFile=dir+"/energy_uj";
      if(!isFile(maxRangeFile)||!isFile(energyFile))
      {
        break;
      }
      int fd=openR(maxRangeFile);
      maxRange.emplace_back(readValue(fd));
      close(fd);
      fd=openR(energyFile);
      initValue.emplace_back(readValue(fd));
      energyFd.emplace_back(fd);
    }
    if(empty(energyFd))
    {
      available=false;
      return 0.0;
    }
  }
  int64_t energy=0;
  for(int i=0, i_end=len(energyFd); i<i_end; ++i)
  {
    const int fd=energyFd[i];
    lseek(fd, 0, SEEK_SET);
    const int64_t value=readValue(fd);
    const int64_t range=maxRange[i];
    energy+=(value+range-initValue[i])%range;
  }
  return double(energy)*1e-6; // micro-joules to joules
}

std::string // textual description of current call stack
computeStackTrace()
{
  // nb: don't use crs:: system calls in order to prevent from
  //     recursive callstack retrieval on errors 
  std::string result;
  constexpr int maxStackSize=0x100;
  void *stack[maxStackSize];
#if defined _WIN32
  HANDLE hProcess=::GetCurrentProcess();
  if(::SymInitialize(hProcess, nullptr, TRUE))
  {
    const int stackDepth=::CaptureStackBackTrace(0, maxStackSize,
                                                 stack, nullptr);
    std::array<char, sizeof(SYMBOL_INFO)+MAX_SYM_NAME*sizeof(TCHAR)> buffer;
    auto symbol=reinterpret_cast<SYMBOL_INFO *>(data(buffer));
    symbol->SizeOfStruct=sizeof(SYMBOL_INFO);
    symbol->MaxNameLen=MAX_SYM_NAME;
    IMAGEHLP_LINE64 line;
    line.SizeOfStruct=sizeof(IMAGEHLP_LINE64);
    for(int topLevel=0, level=0; level<stackDepth; ++level)
    {
      // FIXME: this works only with PDB files.
      //        Visual-Studio /debug linker switch produces such files
      //        unfortunately, mingw-w64 does not.
      DWORD disp=0;
      if(::SymFromAddr(hProcess, DWORD64(stack[level]), nullptr, symbol)&&
         ::SymGetLineFromAddr64(hProcess, DWORD64(stack[level]), &disp, &line))
      {
        if(!topLevel&&std::strstr(symbol->Name, __func__))
        {
          topLevel=level+1;
        }
        if(topLevel&&(level>=topLevel))
        {
          result+='[';
          result+=std::to_string(level-topLevel);
          result+="] ";
          result+=symbol->Name;
          result+=" at ";
          result+=line.FileName;
          result+=':';
          result+=std::to_string(line.LineNumber);
          result+='\n';
        }
        if(!std::strcmp(symbol->Name, "main"))
        {
          break;
        }
      }
    }
  }
#else
  const int stackDepth=::backtrace(stack, maxStackSize);
  // FIXME: a solution could hardly be uglier than this one!
  //        (retrieving information from an external program)
  auto useCommand=[&stack, &stackDepth, &thisFnct=__func__](auto &strArgs)
  {
    for(int i=0; i<stackDepth; ++i)
    {
      std::ostringstream oss;
      oss << stack[i];
      strArgs.emplace_back(oss.str());
    }
    std::vector<const char *> args{size(strArgs)+1};
    std::transform(begin(strArgs), end(strArgs), begin(args),
      [](auto &s)
      {
        return data(s);
      });
    int fifo[2];
    ::pipe(fifo);
    pid_t child=::fork();
    if(child==0)
    {
      ::close(fifo[0]);
      ::close(STDIN_FILENO);
      // ::close(STDERR_FILENO);
      ::dup2(fifo[1], STDOUT_FILENO);
      ::close(fifo[1]);
      ::execvp(args[0], const_cast<char **>(data(args)));
      ::exit(1);
    }
    ::close(fifo[1]);
    std::string currentLine;
    std::vector<std::string> lines;
    for(;;)
    {
      char c;
      int r;
      RESTART_SYSCALL(r, int(::read(fifo[0], &c, 1)));
      if(r<1)
      {
        break;
      }
      if(c!='\n')
      {
        currentLine+=c;
      }
      else if(!empty(currentLine))
      {
        lines.emplace_back(std::move(currentLine));
        currentLine.clear();
      }
    }
    ::close(fifo[0]);
    ::waitpid(child, nullptr, 0);
    int thisLevel=-1, mainLevel=-1;
    for(const auto &line: lines)
    {
      if((thisLevel==-1)&&std::strstr(data(line), thisFnct))
      {
        thisLevel=int(&line-&lines.front());
      }
      else if((mainLevel==-1)&&
               (!std::strncmp(data(line), "main ", 5)||
                !std::strncmp(data(line), "main(", 5)))
      {
        mainLevel=int(&line-&lines.front());
      }      
    }
    if((mainLevel!=-1)&&(thisLevel<mainLevel))
    {
      lines.erase(cbegin(lines)+mainLevel+1, cend(lines));
    }
    if(thisLevel!=-1)
    {
      lines.erase(cbegin(lines), cbegin(lines)+thisLevel+1);
    }
    std::string result;
    for(const auto &line: lines)
    {
      result+='[';
      result+=std::to_string(&line-&lines.front());
      result+="] ";
      result+=line;
      result+='\n';
    }
    return result;
  };
#if defined __APPLE__
  std::vector<std::string> args{"atos",
                                "-p", std::to_string(::getpid())};
  result=useCommand(args);
#else
  std::vector<std::string> args{"eu-addr2line",
                                "-f", "-C", "-s", "--pretty-print",
                                "-p", std::to_string(::getpid())};
  result=useCommand(args);
#endif
  if(empty(result)) // fallback
  {
    // FIXME: this cannot work since stack addresses need to be converted
    //        to executable addresses as atos and eu-addr2line do
#if 0
    // see https://stackoverflow.com/questions/1023306/finding-current-executables-path-without-proc-self-exe
    std::string executable;
    char buffer[PATH_MAX]={'\0'};
#if defined _WIN32
    if(::GetModuleFileName(nullptr, buffer, sizeof(buffer)))
#elif defined __APPLE__
    if(::proc_pidpath(::getpid(), buffer, sizeof(buffer))>0)
#else
    if(::readlink("/proc/self/exe", buffer, sizeof(buffer))>0)
#endif
    {
      executable=buffer;
    }
    std::vector<std::string> args{"addr2line",
                                  "-f", "-C", "-s", "--pretty-print",
                                  "-e", executable};
    result=useCommand(args);
#endif
  }
#endif
  if(empty(result))
  {
    result+="!!! cannot retrieve stack-trace details\n";
#if defined _MSC_VER
    result+="!!! link with the '/debug' switch to generate a .pdb file\n";
#elif defined _WIN32
    result+="!!! ('gcc' does not generate .pdb files, 'cv2pdb' may help)";
#elif defined __APPLE__
    result+="!!! ('atos' command gave nothing)";
#else
    result+="!!! ('eu-addr2line' command gave nothing)";
#endif
  }
  return result;
}

//----------------------------------------------------------------------------

std::string // text description of error code
strerror(int errorCode)
{
  std::string result;
#if defined _WIN32
  char *err;
  if(::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
                     (LPCVOID)0, errorCode,
                     0, // MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                     (LPTSTR)&err, 4096, nullptr))
  {
    for(int i=int(::strlen(err)); i--; )
    {
      if((err[i]!='\r')&&(err[i]!='\n'))
      {
        break;
      }
      err[i]='\0';
    }
    result+=err;
    ::LocalFree((HLOCAL)err);
  }
  else
  {
    result="???";
  }
#else
  result=::strerror(errorCode);
#endif
  result+=txt(" (%)", errorCode);
  return result;
}

std::string // value of environment variable or "" (not set)
getenv(const std::string &name)
{
  const char *v{::getenv(data(name))};
  return std::string{v ? v : ""};
}

void
setenv(const std::string &name,
       const std::string &value)
{
#if defined _WIN32
  (void)name; // avoid ``unused parameter'' warning
  (void)value;
  THROW_NOT_AVAILABLE(" on Windows");
#else
  int r;
  if(empty(value))
  {
    RESTART_SYSCALL(r, ::unsetenv(data(name)));
  }
  else
  {
    RESTART_SYSCALL(r, ::setenv(data(name), data(value), 1));
  }
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
#endif
}

double // seconds since 1970/01/01 00:00:00 UTC
gettimeofday()
{
#if defined _MSC_VER
  FILETIME ft;
  ::GetSystemTimeAsFileTime(&ft);
  int64_t t{(int64_t(ft.dwHighDateTime)<<32)+int64_t(ft.dwLowDateTime)};
  return 1e-6*((t/10LL)-11644473600000000LL); // 100ns to 1us, 1601 to 1970
#else
  struct timeval tv;
  int r;
  RESTART_SYSCALL(r, ::gettimeofday(&tv, nullptr));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
  return double(tv.tv_sec)+1e-6*double(tv.tv_usec);
#endif
}

void
sleep(double seconds)
{
#if defined _MSC_VER
  ::Sleep(DWORD(1e3*seconds));
#else
  struct timespec ts;
  ts.tv_sec=time_t(seconds);
  ts.tv_nsec=int(1e9*(seconds-double(ts.tv_sec)));
  int r;
  RESTART_SYSCALL(r, ::nanosleep(&ts,&ts));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
#endif
}

pid_t // current process identifier
getpid()
{
#if defined _WIN32
  THROW_NOT_AVAILABLE(" on Windows");
  return -1; // never reached
#else
  pid_t p;
  RESTART_SYSCALL(p, ::getpid());
  if(p==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
  return p;
#endif
}

pid_t // parent process identifier
getppid()
{
#if defined _WIN32
  THROW_NOT_AVAILABLE(" on Windows");
  return -1; // never reached
#else
  pid_t p;
  RESTART_SYSCALL(p, ::getppid());
  if(p==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
  return p;
#endif
}

pid_t // new process identifier (in parent process) or 0 (in child process)
fork()
{
#if defined _WIN32
  THROW_NOT_AVAILABLE(" on Windows");
  return -1; // never reached
#else
  pid_t p;
  RESTART_SYSCALL(p, ::fork());
  if(p==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
  return p;
#endif
}

[[noreturn]]
void
exit(int status)
{
  if((status<0)||(status>255))
  {
  throw std::runtime_error{txt("%:%:%() status % not in [0;255]\n%",
                               __FILE__, __LINE__, __func__,
                               status, computeStackTrace())};
  }
  ::exit(status);
}

std::tuple<pid_t, // pid of child process or 0 (if nonblocking)
           int,   // status or -1
           int>   // signal or -1
waitpid(pid_t child,
        bool nonblocking)
{
  pid_t p=0;
  int status=-1;
  int signal=-1;
#if defined _WIN32
  (void)child; // avoid ``unused parameter'' warning
  (void)nonblocking;
  THROW_NOT_AVAILABLE(" on Windows");
#else
  int wstatus;
  RESTART_SYSCALL(p, ::waitpid(child, &wstatus, nonblocking ? WNOHANG : 0));
  if((p==-1)&&!nonblocking)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
  if(p>0)
  {
    if(WIFEXITED(wstatus))
    {
      status=WEXITSTATUS(wstatus);
    }
    if(WIFSIGNALED(wstatus))
    {
      signal=WTERMSIG(wstatus);
    }
  }
  else
  {
    p=0;
  }
#endif
  return {std::move(p),
          std::move(status),
          std::move(signal)};
}

std::string
strsignal(int signal)
{
#if defined _WIN32
  (void)signal; // avoid ``unused parameter'' warning
  THROW_NOT_AVAILABLE(" on Windows");
  return {}; // never reached
#else
  const char *s{signal==-1 ? "none" : ::strsignal(signal)};
  return std::string{s ? s : "unknown"};
#endif
}

#if !defined _WIN32
static
void
sigaction_handler_(int signal)
{
  std::function<void(int)> action{nullptr};
  while(sigaction_lock_.test_and_set(std::memory_order_acquire)) { }
  if(auto it=sigaction_data_.find(signal); it!=end(sigaction_data_))
  {
    action=it->second;
  }
  sigaction_lock_.clear(std::memory_order_release);
  if(action)
  {
    action(signal);
  }
}
#endif

void
sigaction(int signal,
          std::function<void(int)> action)
{
#if defined _WIN32
  (void)signal; // avoid ``unused parameter'' warning
  (void)action;
  THROW_NOT_AVAILABLE(" on Windows");
#else
  struct sigaction sa;
  ::memset(&sa, 0, sizeof(sa));
  sa.sa_handler=SIG_DFL;
  if(action)
  {
    while(sigaction_lock_.test_and_set(std::memory_order_acquire)) { }
    sigaction_data_[signal]=action;
    sigaction_lock_.clear(std::memory_order_release);
    sa.sa_handler=sigaction_handler_;
  }
  int r;
  RESTART_SYSCALL(r, ::sigaction(signal, &sa, nullptr));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
#endif
}

std::tuple<int, // read file-descriptor
           int> // write file-descriptor
pipe()
{
  std::array<int, 2> fd{-1, -1};
#if defined _WIN32
  THROW_NOT_AVAILABLE(" on Windows");
#else
  int r;
  RESTART_SYSCALL(r, ::pipe(data(fd)));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
#endif
  return {std::move(fd[0]),
          std::move(fd[1])};
}

std::tuple<SOCKET, // local socket for one end
           SOCKET> // local socket for the other end
socketpair(int type)
{
  std::array<SOCKET, 2> fd{INVALID_SOCKET, INVALID_SOCKET};
#if defined _WIN32
  (void)type; // avoid ``unused parameter'' warning
  THROW_NOT_AVAILABLE(" on Windows");
#else
  int r;
  RESTART_SYSCALL(r, ::socketpair(PF_LOCAL, type, 0, data(fd)));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
#endif
  return {std::move(fd[0]),
          std::move(fd[1])};
}

int // new file-descriptor
dup(int fd)
{
  int r;
#if defined _MSC_VER
  RESTART_SYSCALL(r, ::_dup(fd));
#else
  RESTART_SYSCALL(r, ::dup(fd));
#endif
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
  return r;
}

int // new file-descriptor (newFd)
dup2(int oldFd,
     int newFd)
{
  int r;
#if defined _MSC_VER
  RESTART_SYSCALL(r, ::_dup2(oldFd, newFd));
#else
  RESTART_SYSCALL(r, ::dup2(oldFd, newFd));
#endif
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
  return r;
}

[[noreturn]]
void
exec(const std::vector<std::string> &commandLine)
{
  std::vector<const char *> args;
  for(const auto &elem: commandLine)
  {
    args.emplace_back(data(elem));
  }
  args.emplace_back(nullptr);
#if defined _MSC_VER
  ::_execvp(args[0], const_cast<char **>(data(args)));
#else
  ::execvp(args[0], const_cast<char **>(data(args)));
#endif
  THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
}

void * // shared memory address
mmap_shared(int byteCount)
{
#if defined _WIN32
  (void)byteCount; // avoid ``unused parameter'' warning
  THROW_NOT_AVAILABLE(" on Windows");
  return nullptr; // never reached
#else
  void *p=::mmap(nullptr, byteCount, PROT_READ|PROT_WRITE,
                 MAP_ANONYMOUS|MAP_SHARED, -1, 0);
  if(p==MAP_FAILED)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
  return p;
#endif
}

void 
munmap(void *address,
       int byteCount)
{
#if defined _WIN32
  (void)address; // avoid ``unused parameter'' warning
  (void)byteCount;
  THROW_NOT_AVAILABLE(" on Windows");
#else
  int r;
  RESTART_SYSCALL(r, ::munmap(address, byteCount));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
#endif
}

std::vector<CpuInfo> // detected package and core of each CPU in the system
detectCpuInfo(bool enableSmt)
{
  std::vector<CpuInfo> result;
  int cpuCount{int(std::thread::hardware_concurrency())};
#if defined __linux__
  for(int cpuId=0;cpuId<cpuCount;++cpuId)
  {
    auto pfx{txt("/sys/devices/system/cpu/cpu%", cpuId)};
    int coreId{-1}, pkgId{-1};
    std::ifstream{txt("%/topology/core_id", pfx)} >> coreId;
    std::ifstream{txt("%/topology/physical_package_id", pfx)} >> pkgId;
    if((coreId<0)||(pkgId<0))
    {
      continue;
    }
    if(enableSmt||
       std::none_of(cbegin(result), cend(result),
         [pkgId, coreId](const CpuInfo &c)
         {
           return (c.pkgId==pkgId)&&(c.coreId==coreId);
         }))
    {
      result.emplace_back(CpuInfo{pkgId, coreId, cpuId});
    }
  }
#else
  (void)enableSmt; // avoid ``unused parameter'' warning
#endif
  if(empty(result))
  {
    // nothing found, assume one package and one core per CPU
    for(int cpuId=0; cpuId<cpuCount; ++cpuId)
    {
      result.emplace_back(CpuInfo{0, cpuId, cpuId});
    }
  }
  return result;
}

void
bindCurrentThreadToCpu(int cpuId)
{
#if defined __linux__
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(cpuId, &cpuset);
  int r=::pthread_setaffinity_np(::pthread_self(), sizeof(cpuset), &cpuset);
  if(r!=0)
  {
    THROW_SYSTEM_FAILURE(r);
  }
#elif defined _WIN32
  DWORD_PTR r=::SetThreadAffinityMask(::GetCurrentThread(),
                                      DWORD_PTR(1ULL<<cpuId));
  if(!r)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
#else
  (void)cpuId; // avoid ``unused parameter'' warning
#endif
}

//----------------------------------------------------------------------------

std::vector<std::string> // directory entries (except . and ..)
listDir(const std::string &path)
{
  std::vector<std::string> result;
#if defined _MSC_VER
  std::string pattern{path};
  if(empty(pattern))
  {
    pattern='.';
  }
  if(pattern.back()!='\\')
  {
    pattern+='\\';
  }
  pattern+="*.*";
  WIN32_FIND_DATA findData;
  HANDLE findHandle{::FindFirstFile(data(pattern), &findData)};
  if(findHandle==INVALID_HANDLE_VALUE)
  {
    DWORD err{GetLastError()};
    if(err!=ERROR_FILE_NOT_FOUND)
    {
      THROW_SYSTEM_FAILURE(err);
    }
  }
  else
  {
    do
    {
      if(::strcmp(findData.cFileName, ".")&&
         ::strcmp(findData.cFileName, ".."))
      {
        result.emplace_back(findData.cFileName);
      }
    } while(::FindNextFile(findHandle, &findData));
    ::FindClose(findHandle);
  }
#else
  DIR *d{opendir(data(path))};
  if(!d)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
  for( ; ; )
  {
    struct dirent *e{::readdir(d)};
    if(!e)
    {
      break; // end of directory
    }
    if(::strcmp(e->d_name, ".")&&::strcmp(e->d_name, ".."))
    {
      result.emplace_back(e->d_name);
    }
  }
  int r;
  RESTART_SYSCALL(r, ::closedir(d));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
#endif
  return result;
}

bool // path exists and conforms to mode
access(const std::string &path,
       int mode)
{
  int r;
#if defined _WIN32
  if(mode&X_OK)
  {
    mode=(mode&~X_OK)|R_OK; // substitute X with R
  }
#endif
#if defined _MSC_VER
  RESTART_SYSCALL(r, ::_access(data(path), mode));
#else
  RESTART_SYSCALL(r, ::access(data(path), mode));
#endif
  return r!=-1;
}

int // file size or -1 (no file)
fileSize(const std::string &path)
{
  int r;
#if defined _MSC_VER
  struct _stat st;
  RESTART_SYSCALL(r, ::_stat(data(path), &st));
#else
  struct stat st;
  RESTART_SYSCALL(r, ::stat(data(path), &st));
#endif
  return (r!=-1) ? int(st.st_size) : -1;
}

bool // path exists and is a file
isFile(const std::string &path)
{
#if defined _MSC_VER
  struct _stat st;
  int r;
  RESTART_SYSCALL(r, ::_stat(data(path), &st));
  return (r!=-1)&&(st.st_mode&_S_IFREG);
#else
  struct stat st;
  int r;
  RESTART_SYSCALL(r, ::stat(data(path), &st));
  return (r!=-1)&&((st.st_mode&S_IFMT)==S_IFREG);
#endif
}

bool // path exists and is a directory
isDir(const std::string &path)
{
#if defined _MSC_VER
  struct _stat st;
  int r;
  RESTART_SYSCALL(r, ::_stat(data(path), &st));
  return (r!=-1)&&(st.st_mode&_S_IFDIR);
#else
  struct stat st;
  int r;
# if defined _WIN32 // FIXME: ugly bug with trailing '/' or '\\' in mingw!
  if(!empty(path)&&((path.back()=='/')||(path.back()=='\\')))
  {
    std::string tmp{path, 0, size(path)-1};
    while(!empty(tmp)&&((tmp.back()=='/')||(tmp.back()=='\\')))
    {
      tmp.pop_back();
    }
    if(empty(tmp)||tmp.back()==':')
    {
      tmp.push_back(path.back());
    }
    RESTART_SYSCALL(r, ::stat(data(tmp), &st));
  }
  else // execute the normal syscall
#endif
  RESTART_SYSCALL(r, ::stat(data(path), &st));
  return (r!=-1)&&((st.st_mode&S_IFMT)==S_IFDIR);
#endif
}

bool // path exists and is a named pipe
isFifo(const std::string &path)
{
#if defined _WIN32
  (void)path; // avoid ``unused parameter'' warning
  return false; // does not exist under windows
#else
  struct stat st;
  int r;
  RESTART_SYSCALL(r, ::stat(data(path), &st));
  return (r!=-1)&&((st.st_mode&S_IFMT)==S_IFIFO);
#endif
}

void
mkdir(const std::string &path)
{
  int r;
#if defined _MSC_VER
  RESTART_SYSCALL(r, ::_mkdir(data(path)));
#elif defined _WIN32
  RESTART_SYSCALL(r, ::mkdir(data(path)));
#else
  RESTART_SYSCALL(r, ::mkdir(data(path),0777));
#endif
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
}

void
rmdir(const std::string &path)
{
  int r;
#if defined _MSC_VER
  RESTART_SYSCALL(r, ::_rmdir(data(path)));
#else
  RESTART_SYSCALL(r, ::rmdir(data(path)));
#endif
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
}

void
mkfifo(const std::string &path)
{
#if defined _WIN32
  (void)path; // avoid ``unused parameter'' warning
  THROW_NOT_AVAILABLE(" on Windows");
#else
  int r;
  RESTART_SYSCALL(r, ::mkfifo(data(path), 0666));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
#endif
}

static
int // file-descriptor
open_(const std::string &path,
      int mode,
      int rights=0666)
{
  int r;
#if defined _MSC_VER
  RESTART_SYSCALL(r, ::_open(data(path), mode, rights));
#else
  RESTART_SYSCALL(r, ::open(data(path), mode, rights));
#endif
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
  return r;
}

int // read-only file-descriptor
openR(const std::string &path)
{
  return open_(path, O_RDONLY);
}

int // write-only file-descriptor
openW(const std::string &path,
      bool append,
      bool exclusive)
{
  int mode{O_WRONLY|O_CREAT};
  mode|=(append ? O_APPEND : O_TRUNC);
  if(exclusive)
  {
    mode|=O_EXCL;
  }
  return open_(path, mode);
}

int // read-write file-descriptor
openRW(const std::string &path)
{
  return open_(path, O_RDWR|O_CREAT);
}

int // new absolute offset
lseek(int fd,
      int offset,
      int origin)
{
  int r;
#if defined _MSC_VER
  RESTART_SYSCALL(r, int(::_lseek(fd, offset, origin)));
#else
  RESTART_SYSCALL(r, int(::lseek(fd, offset, origin)));
#endif
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
  return r;
}

void
close(int fd)
{
  int r;
#if defined _MSC_VER
  RESTART_SYSCALL(r, ::_close(fd));
#else
  RESTART_SYSCALL(r, ::close(fd));
#endif
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
}

void
unlink(const std::string &path)
{
  int r;
#if defined _MSC_VER
  RESTART_SYSCALL(r, ::_unlink(data(path)));
#else
  RESTART_SYSCALL(r, ::unlink(data(path)));
#endif
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
}

int // written bytes
write(int fd,
      const void *content,
      int contentSize)
{
  auto ptr{reinterpret_cast<const char *>(content)};
  int r;
#if defined _MSC_VER
  RESTART_SYSCALL(r, int(::_write(fd, ptr, contentSize)));
#else
  RESTART_SYSCALL(r, int(::write(fd, ptr, contentSize)));
#endif
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
  return r;
}

int // written bytes (contentSize expected)
writeAll(int fd,
         const void *content,
         int contentSize)
{
  return writeAll_<int>(fd, content, contentSize,
         static_cast<int (*)(int, const void *, int)>(crs::write));
}

int // written bytes (len(msg) expected)
writeAll(int fd,
         const std::string &msg)
{
  return writeAll_<int>(fd, msg,
         static_cast<int (*)(int, const void *, int)>(crs::writeAll));
}

int // read bytes or 0 (EOF)
read(int fd,
     void *buffer,
     int bufferCapacity)
{
  auto ptr{reinterpret_cast<char *>(buffer)};
  int r;
#if defined _MSC_VER
  RESTART_SYSCALL(r, int(::_read(fd, ptr, bufferCapacity)));
#else
  RESTART_SYSCALL(r, int(::read(fd, ptr, bufferCapacity)));
#endif
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SYSCALL_ERRNO);
  }
  return r;
}

int // read bytes (bufferCapacity expected) or 0 (EOF)
readAll(int fd,
        void *buffer,
        int bufferCapacity)
{
  return readAll_<int>(fd, buffer, bufferCapacity,
         static_cast<int (*)(int, void *, int)>(crs::read));
}

std::string // read text or "" (EOF)
read(int fd,
     int capacity)
{
  return read_<int>(fd, capacity,
         static_cast<int (*)(int, void *, int)>(crs::read));
}

std::string // read text or "" (EOF)
readAll(int fd,
        int capacity)
{
  return readAll_<int>(fd, capacity,
         static_cast<int (*)(int, void *, int)>(crs::readAll));
}

std::string // read text line or "" (EOF)
readLine(int fd)
{
  return readLine_<int>(fd,
         static_cast<int (*)(int, void *, int)>(crs::read));
}

//----------------------------------------------------------------------------

uint32_t // IPv4 address of dotted-decimal text or 0
parseIpv4Address(const std::string &address)
{
  uint32_t b3, b2, b1, b0;
  if((::sscanf(data(address), " %u.%u.%u.%u ", &b3, &b2, &b1, &b0)!=4)||
     (b3>0x000000FF)||(b2>0x000000FF)||(b1>0x000000FF)||(b0>0x000000FF))
  {
    return 0;
  }
  return ((b3<<24)|(b2<<16)|(b1<<8)|(b0<<0));
}

std::string // dotted-decimal text of IPv4 address
formatIpv4Address(uint32_t address)
{
  return txt("%.%.%.%",
             (address>>24)&0x000000FF,
             (address>>16)&0x000000FF,
             (address>>8)&0x000000FF,
             (address>>0)&0x000000FF);
}

std::string
gethostname()
{
  std::string result;
  uninitialised_resize(result, 0x100);
  int r;
  RESTART_SYSCALL(r, ::gethostname(data(result), len(result)));
  result.resize(::strlen(data(result)));
  return result;
}

uint32_t // IPv4 address of host name
gethostbyname(const std::string &hostname)
{
  uint32_t addr{0};
  struct hostent *host{::gethostbyname(data(hostname))};
  if(host)
  {
#if defined __APPLE__ && defined __clang__
    // alignment problem with apple's standard library
    uint8_t *ptr=nullptr;
    std::memcpy(&ptr, &host->h_addr, sizeof(ptr));
    addr=(uint32_t(ptr[0])<<24)
        |(uint32_t(ptr[1])<<16)
        |(uint32_t(ptr[2])<<8)
        |(uint32_t(ptr[3])<<0);
#else
    addr=ntohl(*reinterpret_cast<uint32_t *>(host->h_addr));
#endif
  }
  else
  {
    addr=parseIpv4Address(hostname); // try dotted-decimal notation
  }
  if(!addr)
  {
    throw std::runtime_error{txt("%:%:%() unknown host '%'\n%",
                                 __FILE__, __LINE__, __func__,
                                 hostname, computeStackTrace())};
  }
  return addr;
}

SOCKET
socket(int domain,
       int type,
       int protocol)
{
  SOCKET s;
  RESTART_SYSCALL(s, ::socket(domain, type, protocol));
  if(s==INVALID_SOCKET)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
  return s;
}

#if defined _WIN32
  // Windows sockets are handled through the SOCKET type which actualy is a
  // ``long long int'', thus the previously defined close(int) function will
  // be used for usual file-descriptors whereas this close(SOCKET) function
  // will be used for sockets.
  void
  close(SOCKET s)
  {
    int r;
    RESTART_SYSCALL(r, ::closesocket(s));
    if(r==-1)
    {
      THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
    }
  }
#else
  // anywhere else a socket is simply a file-descriptor thus the
  // previously defined close(int) function will be used in both cases.
#endif

void
shutdown(SOCKET s,
         int how)
{
  int r;
  RESTART_SYSCALL(r, ::shutdown(s, how));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
}

void
setReuseAddrOption(SOCKET s,
                   bool on)
{
#if defined _WIN32
  BOOL option=on ? TRUE : FALSE;
#else
  int option=on ? 1 : 0;
#endif
  auto opt{reinterpret_cast<const char *>(&option)};
  int r;
  RESTART_SYSCALL(r, ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                                  opt, sizeof(option)));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
}

void
setTcpNodelayOption(SOCKET s,
                    bool on)
{
#if defined _WIN32
  BOOL option=on ? TRUE : FALSE;
#else
  int option=on ? 1 : 0;
#endif
  auto opt{reinterpret_cast<const char *>(&option)};
  int r;
  RESTART_SYSCALL(r, ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                                  opt, sizeof(option)));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
}

void
setBroadcastOption(SOCKET s,
                   bool on)
{
#if defined _WIN32
  BOOL option=on ? TRUE : FALSE;
#else
  int option=on ? 1 : 0;
#endif
  auto opt{reinterpret_cast<const char *>(&option)};
  int r;
  RESTART_SYSCALL(r, ::setsockopt(s, SOL_SOCKET, SO_BROADCAST,
                                  opt, sizeof(option)));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
}

void
bind(SOCKET s,
     uint32_t address,
     uint16_t port)
{
  struct sockaddr_in addr;
  socklen_t addrLen{socklen_t(sizeof(addr))};
  ::memset(&addr, 0, addrLen);
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  addr.sin_addr.s_addr=htonl(address);
  auto sa{reinterpret_cast<const struct sockaddr *>(&addr)};
  int r;
  RESTART_SYSCALL(r, ::bind(s, sa, addrLen));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
}

void
bind(SOCKET s,
     uint16_t port)
{
  return bind(s, INADDR_ANY, port);
}

std::tuple<uint32_t, // IPv4 address
           uint16_t> // port number
getsockname(SOCKET s)
{
  struct sockaddr_in addr;
  socklen_t addrLen{socklen_t(sizeof(addr))};
  auto sa{reinterpret_cast<struct sockaddr *>(&addr)};
  int r;
  RESTART_SYSCALL(r, ::getsockname(s, sa, &addrLen));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
  return {std::move(ntohl(addr.sin_addr.s_addr)),
          std::move(ntohs(addr.sin_port))};
}

std::tuple<uint32_t, // IPv4 address
           uint16_t> // port number
getpeername(SOCKET s)
{
  struct sockaddr_in addr;
  socklen_t addrLen{socklen_t(sizeof(addr))};
  auto sa{reinterpret_cast<struct sockaddr *>(&addr)};
  int r;
  RESTART_SYSCALL(r, ::getpeername(s, sa, &addrLen));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
  return {std::move(ntohl(addr.sin_addr.s_addr)),
          std::move(ntohs(addr.sin_port))};
}

void
listen(SOCKET s,
       int backlog)
{
  int r;
  RESTART_SYSCALL(r, ::listen(s, backlog));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
}

std::tuple<SOCKET,   // dialog socket
           uint32_t, // IPv4 address
           uint16_t> // port number
acceptfrom(SOCKET listenSocket)
{
  struct sockaddr_in addr;
  socklen_t addrLen{socklen_t(sizeof(addr))};
  auto sa{reinterpret_cast<struct sockaddr *>(&addr)};
  SOCKET s;
  RESTART_SYSCALL(s, ::accept(listenSocket, sa, &addrLen));
  if(s==INVALID_SOCKET)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
  return {std::move(s),
          std::move(ntohl(addr.sin_addr.s_addr)),
          std::move(ntohs(addr.sin_port))};
}

SOCKET // dialog socket
accept(SOCKET listenSocket)
{
  auto [s, address, port]=acceptfrom(listenSocket);
  (void)address; // avoid ``unused variable'' warning
  (void)port;
  return s;
}

void
connect(SOCKET s,
        uint32_t address,
        uint16_t port)
{
  struct sockaddr_in addr;
  socklen_t addrLen{socklen_t(sizeof(addr))};
  ::memset(&addr, 0, addrLen);
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  addr.sin_addr.s_addr=htonl(address);
  auto sa{reinterpret_cast<const struct sockaddr *>(&addr)};
  int r;
  RESTART_SYSCALL(r, ::connect(s, sa, addrLen));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
}

int // sent bytes
send(SOCKET s,
     const void *content,
     int contentSize)
{
  auto ptr{reinterpret_cast<const char *>(content)};
  int r;
  RESTART_SYSCALL(r, int(::send(s, ptr, contentSize, 0)));
#if defined _WIN32
  if((r==-1)&&(SOCKET_ERRNO==WSAECONNRESET))
  {
    r=0; // ugly hack!
  }
#endif
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
  return r;
}

int // sent bytes (contentSize expected)
sendAll(SOCKET s,
        const void *content,
        int contentSize)
{
  return writeAll_<SOCKET>(s, content, contentSize,
         static_cast<int (*)(SOCKET, const void *, int)>(crs::send));
}

int // sent bytes (len(msg) expected)
sendAll(SOCKET s,
        const std::string &msg)
{
  return writeAll_<SOCKET>(s, msg,
         static_cast<int (*)(SOCKET, const void *, int)>(crs::sendAll));
}

int // sent bytes
sendto(SOCKET s,
       const void *content,
       int contentSize,
       uint32_t address,
       uint16_t port)
{
  auto ptr{reinterpret_cast<const char *>(content)};
  struct sockaddr_in addr;
  socklen_t addrLen{socklen_t(sizeof(addr))};
  ::memset(&addr, 0, addrLen);
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  addr.sin_addr.s_addr=htonl(address);
  auto sa{reinterpret_cast<const struct sockaddr *>(&addr)};
  int r;
  RESTART_SYSCALL(r, int(::sendto(s, ptr, contentSize, 0, sa, addrLen)));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
  return r;
}

int // sent bytes
sendto(SOCKET s,
       const std::string &msg,
       uint32_t address,
       uint16_t port)
{
  return sendto(s, data(msg), len(msg), address, port);
}

int // received bytes or 0 (EOF)
recv(SOCKET s,
     void *buffer,
     int bufferCapacity)
{
  auto ptr{reinterpret_cast<char *>(buffer)};
  int r;
  RESTART_SYSCALL(r, int(::recv(s, ptr, bufferCapacity, 0)));
#if defined _WIN32
  if((r==-1)&&(SOCKET_ERRNO==WSAECONNRESET))
  {
    r=0; // ugly hack!
  }
#endif
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
  return r;
}

int // received bytes (bufferCapacity expected) or 0 (EOF)
recvAll(SOCKET s,
        void *buffer,
        int bufferCapacity)
{
  return readAll_<SOCKET>(s, buffer, bufferCapacity,
         static_cast<int (*)(SOCKET, void *, int)>(crs::recv));
}

std::string // received text or "" (EOF)
recv(SOCKET s,
     int capacity)
{
  return read_<SOCKET>(s, capacity,
         static_cast<int (*)(SOCKET, void *, int)>(crs::recv));
}

std::string // received text or "" (EOF)
recvAll(SOCKET s,
        int capacity)
{
  return readAll_<SOCKET>(s, capacity,
         static_cast<int (*)(SOCKET, void *, int)>(crs::recvAll));
}

std::string // received text line or "" (EOF)
recvLine(SOCKET s)
{
  return readLine_<SOCKET>(s,
         static_cast<int (*)(SOCKET, void *, int)>(crs::recv));
}

std::tuple<int,      // received bytes or 0 (EOF)
           uint32_t, // IPv4 address
           uint16_t> // port number
recvfrom(SOCKET s,
         void *buffer,
         int bufferCapacity)
{
  auto ptr{reinterpret_cast<char *>(buffer)};
  struct sockaddr_in addr;
  socklen_t addrLen{socklen_t(sizeof(addr))};
  auto sa{reinterpret_cast<struct sockaddr *>(&addr)};
  int r;
  RESTART_SYSCALL(r, int(::recvfrom(s, ptr, bufferCapacity,
                                    0, sa, &addrLen)));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
  return {std::move(r),
          std::move(ntohl(addr.sin_addr.s_addr)),
          std::move(ntohs(addr.sin_port))};
}

std::tuple<std::string, // received text or "" (EOF)
           uint32_t,    // IPv4 address
           uint16_t>    // port number
recvfrom(SOCKET s,
         int capacity)
{
  std::string result;
  uninitialised_resize(result, capacity);
  auto [r, address, port]=recvfrom(s, data(result), capacity);
  result.resize(r);
  return {std::move(result),
          std::move(address),
          std::move(port)};
}

int // number of sockets in ready-state
select(std::vector<SOCKET> &inout_readSet,
       std::vector<SOCKET> &inout_writeSet,
       double timeout)
{
  fd_set readSet, writeSet;
  FD_ZERO(&readSet);
  FD_ZERO(&writeSet);
  SOCKET maxHandle=-1;
  for(const auto &s: inout_readSet)
  {
    FD_SET(s, &readSet);
    maxHandle=std::max(maxHandle, s);
  }
  for(const auto &s: inout_writeSet)
  {
    FD_SET(s, &writeSet);
    maxHandle=std::max(maxHandle, s);
  }
  struct timeval tv;
  if(timeout>=0.0)
  {
#if defined _WIN32
    tv.tv_sec=long(timeout);
    tv.tv_usec=long(1e6*(timeout-double(tv.tv_sec)));
#else
    tv.tv_sec=time_t(timeout);
    tv.tv_usec=int(1e6*(timeout-double(tv.tv_sec)));
#endif
  }
  int r;
  RESTART_SYSCALL(r, ::select((int)maxHandle+1,
                              empty(inout_readSet) ? nullptr : &readSet,
                              empty(inout_writeSet) ? nullptr : &writeSet,
                              nullptr,
                              timeout>=0.0 ? &tv : nullptr));
  if(r==-1)
  {
    THROW_SYSTEM_FAILURE(SOCKET_ERRNO);
  }
  for(int i=len(inout_readSet); i--; )
  {
    if(!FD_ISSET(inout_readSet[i], &readSet))
    {
      inout_readSet[i]=inout_readSet.back();
      inout_readSet.pop_back();
    }
  }
  for(int i=len(inout_writeSet); i--; )
  {
    if(!FD_ISSET(inout_writeSet[i], &writeSet))
    {
      inout_writeSet[i]=inout_writeSet.back();
      inout_writeSet.pop_back();
    }
  }
  return r;
}

int // number of sockets in ready-state
select(std::vector<SOCKET> &inout_readSet,
       double timeout)
{
  std::vector<SOCKET> writeSet;
  return select(inout_readSet, writeSet, timeout);
}

int16_t // value converted to network byte-order
hton_i16(int16_t hostValue)
{
#if BYTE_ORDER==BIG_ENDIAN
  return hostValue;
#else
  union { uint8_t b[2]; int16_t v; } u;
  u.b[0]=uint8_t((hostValue>>8)&0x00FF);
  u.b[1]=uint8_t((hostValue>>0)&0x00FF);
  return u.v;
#endif
}

int16_t // value converted to host byte-order
ntoh_i16(int16_t networkValue)
{
  return hton_i16(networkValue);
}

uint16_t // value converted to network byte-order
hton_ui16(uint16_t hostValue)
{
#if BYTE_ORDER==BIG_ENDIAN
  return hostValue;
#else
  union { uint8_t b[2]; uint16_t v; } u;
  u.b[0]=uint8_t((hostValue>>8)&0x00FF);
  u.b[1]=uint8_t((hostValue>>0)&0x00FF);
  return u.v;
#endif
}

uint16_t // value converted to host byte-order
ntoh_ui16(uint16_t networkValue)
{
  return hton_ui16(networkValue);
}

int32_t // value converted to network byte-order
hton_i32(int32_t hostValue)
{
#if BYTE_ORDER==BIG_ENDIAN
  return hostValue;
#else
  union { uint8_t b[4]; int32_t v; } u;
  u.b[0]=uint8_t((hostValue>>24)&0x00FF);
  u.b[1]=uint8_t((hostValue>>16)&0x00FF);
  u.b[2]=uint8_t((hostValue>>8)&0x00FF);
  u.b[3]=uint8_t((hostValue>>0)&0x00FF);
  return u.v;
#endif
}

int32_t // value converted to host byte-order
ntoh_i32(int32_t networkValue)
{
  return hton_i32(networkValue);
}

uint32_t // value converted to network byte-order
hton_ui32(uint32_t hostValue)
{
#if BYTE_ORDER==BIG_ENDIAN
  return hostValue;
#else
  union { uint8_t b[4]; uint32_t v; } u;
  u.b[0]=uint8_t((hostValue>>24)&0x00FF);
  u.b[1]=uint8_t((hostValue>>16)&0x00FF);
  u.b[2]=uint8_t((hostValue>>8)&0x00FF);
  u.b[3]=uint8_t((hostValue>>0)&0x00FF);
  return u.v;
#endif
}

uint32_t // value converted to host byte-order
ntoh_ui32(uint32_t networkValue)
{
  return hton_ui32(networkValue);
}

int64_t // value converted to network byte-order
hton_i64(int64_t hostValue)
{
#if BYTE_ORDER==BIG_ENDIAN
  return hostValue;
#else
  union { uint8_t b[8]; int64_t v; } u;
  u.b[0]=uint8_t((hostValue>>56)&0x00FF);
  u.b[1]=uint8_t((hostValue>>48)&0x00FF);
  u.b[2]=uint8_t((hostValue>>40)&0x00FF);
  u.b[3]=uint8_t((hostValue>>32)&0x00FF);
  u.b[4]=uint8_t((hostValue>>24)&0x00FF);
  u.b[5]=uint8_t((hostValue>>16)&0x00FF);
  u.b[6]=uint8_t((hostValue>>8)&0x00FF);
  u.b[7]=uint8_t((hostValue>>0)&0x00FF);
  return u.v;
#endif
}

int64_t // value converted to host byte-order
ntoh_i64(int64_t networkValue)
{
  return hton_i64(networkValue);
}

uint64_t // value converted to network byte-order
hton_ui64(uint64_t hostValue)
{
#if BYTE_ORDER==BIG_ENDIAN
  return hostValue;
#else
  union { uint8_t b[8]; uint64_t v; } u;
  u.b[0]=uint8_t((hostValue>>56)&0x00FF);
  u.b[1]=uint8_t((hostValue>>48)&0x00FF);
  u.b[2]=uint8_t((hostValue>>40)&0x00FF);
  u.b[3]=uint8_t((hostValue>>32)&0x00FF);
  u.b[4]=uint8_t((hostValue>>24)&0x00FF);
  u.b[5]=uint8_t((hostValue>>16)&0x00FF);
  u.b[6]=uint8_t((hostValue>>8)&0x00FF);
  u.b[7]=uint8_t((hostValue>>0)&0x00FF);
  return u.v;
#endif
}

uint64_t // value converted to host byte-order
ntoh_ui64(uint64_t networkValue)
{
  return hton_ui64(networkValue);
}

real32_t // value converted to network byte-order
hton_r32(real32_t hostValue)
{
#if BYTE_ORDER==BIG_ENDIAN
  return hostValue;
#else
  union { real32_t v; uint32_t i; } u1, u2;
  u1.v=hostValue;
  u2.i=hton_ui32(u1.i);
  return u2.v;
#endif
}

real32_t // value converted to host byte-order
ntoh_r32(real32_t networkValue)
{
  return hton_r32(networkValue);
}

real64_t // value converted to network byte-order
hton_r64(real64_t hostValue)
{
#if BYTE_ORDER==BIG_ENDIAN
  return hostValue;
#else
  union { real64_t v; uint64_t i; } u1, u2;
  u1.v=hostValue;
  u2.i=hton_ui64(u1.i);
  return u2.v;
#endif
}

real64_t // value converted to host byte-order
ntoh_r64(real64_t networkValue)
{
  return hton_r64(networkValue);
}

//----------------------------------------------------------------------------

#if USE_SSL
  static
  void
  ssl_locking_cb_(int mode,
                  int n,
                  const char *file,
                  int line)
  {
    (void)file; // avoid ``unused parameter'' warning
    (void)line;
    if(mode&CRYPTO_LOCK)
    {
      ssl_locks_[n].lock();
    }
    else
    {
      ssl_locks_[n].unlock();
    }
  }

  static
  unsigned long
  ssl_id_cb_()
  {
    return (unsigned long)::pthread_self();
  }
#endif

SSL_CTX *
sslInit(const std::string &caCertPath,
        const std::string &certPath,
        const std::string &keyPath)
{
#if !USE_SSL
  (void)caCertPath; // avoid ``unused parameter'' warning
  (void)certPath;
  (void)keyPath;
  THROW_NOT_AVAILABLE("");
  return nullptr; // never reached
#else
  ::SSL_library_init();
  ::SSL_load_error_strings();
  ::OpenSSL_add_all_algorithms();
  SSL_CTX *ctx{::SSL_CTX_new(::SSLv23_method())};
  // provide SSL with the list of known CA
  if(!empty(caCertPath)&&
     !::SSL_CTX_load_verify_locations(ctx, data(caCertPath), nullptr))
  {
    THROW_SSL_ERROR(SSL_CTX_load_verify_locations);
  }
  // provide SSL with a certificate/key pair
  if(!empty(certPath)&&!empty(keyPath))
  {
    ::SSL_CTX_use_certificate_file(ctx, data(certPath), SSL_FILETYPE_PEM);
    ::SSL_CTX_use_PrivateKey_file(ctx, data(keyPath), SSL_FILETYPE_PEM);
    if(!::SSL_CTX_check_private_key(ctx))
    {
      THROW_SSL_ERROR(SSL_CTX_check_private_key);
    }
  }
  // provide SSL with multithreading/locking
  (std::vector<std::mutex>(CRYPTO_num_locks())).swap(ssl_locks_); // ugly
  CRYPTO_set_locking_callback(ssl_locking_cb_);
  CRYPTO_set_id_callback(ssl_id_cb_);
  (void)ssl_locking_cb_; // avoid warning with OpenSSL 1.1
  (void)ssl_id_cb_;
  return ctx;
#endif
}

void
sslDestroy(SSL_CTX *ctx)
{
#if !USE_SSL
  (void)ctx; // avoid ``unused parameter'' warning
  THROW_NOT_AVAILABLE("");
#else
  ::SSL_CTX_free(ctx);
  ssl_locks_.clear();
#endif
}

SSL *
sslConnect(SOCKET s,
           SSL_CTX *ctx,
           const std::string &hostname)
{
#if !USE_SSL
  (void)s; // avoid ``unused parameter'' warning
  (void)ctx;
  (void)hostname;
  THROW_NOT_AVAILABLE("");
  return nullptr; // never reached
#else
  SSL *ssl{::SSL_new(ctx)};
  ::SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
  ::SSL_set_fd(ssl, s);
  if(!empty(hostname))
  {
    ::SSL_set_tlsext_host_name(ssl, data(hostname));
    // nb: no need to report an error if this extension is not supported
  }
  if(::SSL_connect(ssl)!=1)
  {
    THROW_SSL_ERROR(SSL_connect);
  }
  if(::SSL_get_verify_result(ssl)!=X509_V_OK)
  {
    err("!!! Warning !!! peer certificate not trusted\n");
  }
  if(!empty(hostname))
  {
    X509 *cert{::SSL_get_peer_certificate(ssl)};
    if(!cert)
    {
      err("!!! Warning !!! %\n", SSL_ERROR_MSG(SSL_get_peer_certificate));
    }
    else
    {
      char commonName[0x100]{""};
      ::X509_NAME_get_text_by_NID(::X509_get_subject_name(cert),
                                  NID_commonName,
                                  commonName, sizeof(commonName));
      if(hostname!=commonName)
      {
        err("!!! Warning !!! Common name '%' != host name '%'\n",
            commonName, hostname);
      }
      ::X509_free(cert);
    }
  }
  return ssl;
#endif
}

SSL *
sslAccept(SOCKET s,
          SSL_CTX *ctx)
{
#if !USE_SSL
  (void)s; // avoid ``unused parameter'' warning
  (void)ctx;
  THROW_NOT_AVAILABLE("");
  return nullptr; // never reached
#else
  SSL *ssl{SSL_new(ctx)};
  ::SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
  ::SSL_set_fd(ssl, s);
  if(::SSL_accept(ssl)!=1)
  {
    THROW_SSL_ERROR(SSL_accept);
  }
  if(::SSL_get_verify_result(ssl)!=X509_V_OK)
  {
    err("!!! Warning !!! peer certificate not trusted\n");
  }
  return ssl;
#endif
}

void
sslClose(SSL *ssl)
{
#if !USE_SSL
  (void)ssl; // avoid ``unused parameter'' warning
  THROW_NOT_AVAILABLE("");
#else
  ::SSL_free(ssl);
#endif
}

int // sent bytes
sslSend(SSL *ssl,
        const void *content,
        int contentSize)
{
#if !USE_SSL
  (void)ssl; // avoid ``unused parameter'' warning
  (void)content;
  (void)contentSize;
  THROW_NOT_AVAILABLE("");
  return 0; // never reached
#else
  auto ptr{reinterpret_cast<const char *>(content)};
  int r=::SSL_write(ssl, ptr, contentSize);
  if(r<0)
  {
    THROW_SSL_ERROR(SSL_write);
  }
  return r;
#endif
}

int // sent bytes (contentSize expected)
sslSendAll(SSL *ssl,
           const void *content,
           int contentSize)
{
  return writeAll_<SSL *>(ssl, content, contentSize,
         static_cast<int (*)(SSL *, const void *, int)>(crs::sslSend));
}

int // sent bytes (len(msg) expected)
sslSendAll(SSL *ssl,
           const std::string &msg)
{
  return writeAll_<SSL *>(ssl, msg,
         static_cast<int (*)(SSL *, const void *, int)>(crs::sslSendAll));
}

bool // some bytes are immediately available
sslPending(SSL *ssl)
{
#if !USE_SSL
  (void)ssl; // avoid ``unused parameter'' warning
  THROW_NOT_AVAILABLE("");
  return false; // never reached
#else
  return ::SSL_pending(ssl)>0;
#endif
}

int // received bytes or 0 (EOF)
sslRecv(SSL *ssl,
        void *buffer,
        int bufferCapacity)
{
#if !USE_SSL
  (void)ssl; // avoid ``unused parameter'' warning
  (void)buffer;
  (void)bufferCapacity;
  THROW_NOT_AVAILABLE("");
  return 0; // never reached
#else
  auto ptr{reinterpret_cast<char *>(buffer)};
  int r=::SSL_read(ssl, ptr, bufferCapacity);
  if(r<0)
  {
    THROW_SSL_ERROR(SSL_read);
  }
  return r;
#endif
}

int // received bytes (bufferCapacity expected) or 0 (EOF)
sslRecvAll(SSL *ssl,
           void *buffer,
           int bufferCapacity)
{
  return readAll_<SSL *>(ssl, buffer, bufferCapacity,
         static_cast<int (*)(SSL *, void *, int)>(crs::sslRecv));
}

std::string // received text or "" (EOF)
sslRecv(SSL *ssl,
        int capacity)
{
  return read_<SSL *>(ssl, capacity,
         static_cast<int (*)(SSL *, void *, int)>(crs::sslRecv));
}

std::string // received text or "" (EOF)
sslRecvAll(SSL *ssl,
           int capacity)
{
  return readAll_<SSL *>(ssl, capacity,
         static_cast<int (*)(SSL *, void *, int)>(crs::sslRecvAll));
}

std::string // received text line or "" (EOF)
sslRecvLine(SSL *ssl)
{
  return readLine_<SSL *>(ssl,
         static_cast<int (*)(SSL *, void *, int)>(crs::sslRecv));
}

} // namespace crs

//----------------------------------------------------------------------------
