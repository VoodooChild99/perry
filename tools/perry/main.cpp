/* -*- mode: c++; c-basic-offset: 2; -*- */

//===-- main.cpp ------------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/ADT/TreeStream.h"
#include "klee/Config/Version.h"
#include "klee/Core/Interpreter.h"
#include "klee/Expr/Expr.h"
#include "klee/ADT/KTest.h"
#include "klee/Support/OptionCategories.h"
#include "klee/Statistics/Statistics.h"
#include "klee/Solver/SolverCmdLine.h"
#include "klee/Support/Debug.h"
#include "klee/Support/ErrorHandling.h"
#include "klee/Support/FileHandling.h"
#include "klee/Support/ModuleUtil.h"
#include "klee/Support/PrintVersion.h"
#include "klee/System/Time.h"
#include "klee/Perry/Passes.h"
#include "klee/Module/Cell.h"
#include "klee/Module/InstructionInfoTable.h"
#include "klee/Module/KModule.h"
#include "klee/Perry/PerryZ3Builder.h"
#include "klee/Perry/PerryUtils.h"
#include "klee/Perry/PerryLoop.h"
#include "klee/Perry/PerryEthInfo.h"
#include "klee/Perry/PerryTimerInfo.h"
#include "klee/Perry/PerryDMAInfo.h"
#include "klee/Perry/PerryCustomHook.h"

#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Errno.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Support/YAMLParser.h"
#include "llvm/Support/YAMLTraits.h"

#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/Signals.h"
#include "llvm/IR/LegacyPassManager.h"


#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <iostream>

#include <cerrno>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <regex>
#include <tuple>

using namespace llvm;
using namespace klee;

namespace {
  cl::opt<Interpreter::TaintOption::Option>
  Taint("taint",
        cl::desc("Taint tracking (default=none)"),
        cl::values(clEnumValN(Interpreter::TaintOption::NoTaint,
                              "none",
                              "Don't do taint tracking (default)"),
                   clEnumValN(Interpreter::TaintOption::DirectTaint,
                              "direct",
                              "Vanilla taint tracking")),
        cl::init(Interpreter::TaintOption::NoTaint));

  cl::opt<bool>
  CollectTaintedCond("collect-state-var",
                     cl::init(false),
                     cl::desc("State Variable Collection (default=false)"));

  cl::opt<std::string>
  PerryOutputFile("perry-out-file",
                  cl::desc("Output file path for Perry"),
                  cl::init(""));

  cl::opt<bool>
  EnableScopeHeuristic("enable-scope-heuristic",
                       cl::init(true),
                       cl::desc("Enable The Scope Heuristic"));

  cl::opt<std::string>
  ARMCPUVersion("arm-cpu-version",
                cl::init(""),
                cl::desc("Specify ARM CPU version"));

  cl::opt<std::string>
  ApiFile("perry-api-file",
          cl::init(""),
          cl::desc("Specify the file containing collected HAL APIs"));

  cl::opt<std::string>
  SuccRetFile("perry-succ-ret-file",
          cl::init(""),
          cl::desc("Specify the file containing successful return values for APIs"));
  
  cl::opt<std::string>
  LoopFile("perry-loop-file",
          cl::init(""),
          cl::desc("Specify the file containing loop information of APIs"));

  cl::opt<std::string>
  InputFile(cl::desc("<input bytecode>"), cl::Positional, cl::init("-"));


  /*** Test case options ***/

  cl::OptionCategory TestCaseCat("Test case options",
                                 "These options select the files to generate for each test case.");

  cl::opt<bool>
  WriteNone("write-no-tests",
            cl::init(false),
            cl::desc("Do not generate any test files (default=false)"),
            cl::cat(TestCaseCat));

  cl::opt<bool>
  WriteCVCs("write-cvcs",
            cl::desc("Write .cvc files for each test case (default=false)"),
            cl::cat(TestCaseCat));

  cl::opt<bool>
  WriteKQueries("write-kqueries",
                cl::desc("Write .kquery files for each test case (default=false)"),
                cl::cat(TestCaseCat));

  cl::opt<bool>
  WriteSMT2s("write-smt2s",
             cl::desc("Write .smt2 (SMT-LIBv2) files for each test case (default=false)"),
             cl::cat(TestCaseCat));

  cl::opt<bool>
  WriteCov("write-cov",
           cl::desc("Write coverage information for each test case (default=false)"),
           cl::cat(TestCaseCat));

  cl::opt<bool>
  WriteTestInfo("write-test-info",
                cl::desc("Write additional test case information (default=false)"),
                cl::cat(TestCaseCat));

  cl::opt<bool>
  WritePaths("write-paths",
             cl::desc("Write .path files for each test case (default=false)"),
             cl::cat(TestCaseCat));

  cl::opt<bool>
  WriteSymPaths("write-sym-paths",
                cl::desc("Write .sym.path files for each test case (default=false)"),
                cl::cat(TestCaseCat));


  /*** Startup options ***/

  cl::OptionCategory StartCat("Startup options",
                              "These options affect how execution is started.");

  cl::opt<std::string>
  EntryPoint("entry-point",
             cl::desc("Function in which to start execution (default=main)"),
             cl::init("main"),
             cl::cat(StartCat));

  cl::opt<std::string>
  RunInDir("run-in-dir",
           cl::desc("Change to the given directory before starting execution (default=location of tested file)."),
           cl::cat(StartCat));
  
  cl::opt<std::string>
  OutputDir("output-dir",
            cl::desc("Directory in which to write results (default=klee-out-<N>)"),
            cl::init(""),
            cl::cat(StartCat));

  cl::opt<bool>
  OptimizeModule("optimize",
                 cl::desc("Optimize the code before execution (default=false)."),
		 cl::init(false),
                 cl::cat(StartCat));

  cl::opt<bool>
  WarnAllExternals("warn-all-external-symbols",
                   cl::desc("Issue a warning on startup for all external symbols (default=false)."),
                   cl::cat(StartCat));
  

  /*** Linking options ***/

  cl::OptionCategory LinkCat("Linking options",
                             "These options control the libraries being linked.");

  // MCU firmwares are self-contained, we therefore need no runtimes
  enum class LibcType { FreestandingLibc, KleeLibc, UcLibc, NopNotNever };

  cl::opt<LibcType> Libc(
      "libc", cl::desc("Choose libc version (none by default)."),
      cl::values(
          clEnumValN(
              LibcType::FreestandingLibc, "none",
              "Don't link in a libc (only provide freestanding environment)"),
          clEnumValN(LibcType::KleeLibc, "klee", "Link in KLEE's libc"),
          clEnumValN(LibcType::UcLibc, "uclibc",
                     "Link in uclibc (adapted for KLEE)"),
          clEnumValN(LibcType::NopNotNever, "nop", "Don't link libc (for real)")),
      cl::init(LibcType::NopNotNever), cl::cat(LinkCat));

  cl::list<std::string>
      LinkLibraries("link-llvm-lib",
                    cl::desc("Link the given bitcode library before execution, "
                             "e.g. .bca, .bc, .a. Can be used multiple times."),
                    cl::value_desc("bitcode library file"), cl::cat(LinkCat));

  cl::opt<bool>
  WithPOSIXRuntime("posix-runtime",
                   cl::desc("Link with POSIX runtime. Options that can be passed as arguments to the programs are: --sym-arg <max-len>  --sym-args <min-argvs> <max-argvs> <max-len> + file model options (default=false)."),
                   cl::init(false),
                   cl::cat(LinkCat));

  cl::opt<std::string> RuntimeBuild(
      "runtime-build",
      cl::desc("Link with versions of the runtime library that were built with "
               "the provided configuration (default=" RUNTIME_CONFIGURATION
               ")."),
      cl::init(RUNTIME_CONFIGURATION), cl::cat(LinkCat));

  /*** Checks options ***/

  cl::OptionCategory ChecksCat("Checks options",
                               "These options control some of the checks being done by KLEE.");

  cl::opt<bool>
  CheckDivZero("check-div-zero",
               cl::desc("Inject checks for division-by-zero (default=true)"),
               cl::init(true),
               cl::cat(ChecksCat));

  cl::opt<bool>
  CheckOvershift("check-overshift",
                 cl::desc("Inject checks for overshift (default=true)"),
                 cl::init(true),
                 cl::cat(ChecksCat));



  cl::opt<bool>
  OptExitOnError("exit-on-error",
                 cl::desc("Exit KLEE if an error in the tested application has been found (default=false)"),
                 cl::init(false),
                 cl::cat(TerminationCat));


  /*** Replaying options ***/
  
  cl::OptionCategory ReplayCat("Replaying options",
                               "These options impact replaying of test cases.");
  
  cl::list<std::string>
  ReplayKTestFile("replay-ktest-file",
                  cl::desc("Specify a ktest file to use for replay"),
                  cl::value_desc("ktest file"),
                  cl::cat(ReplayCat));

  cl::list<std::string>
  ReplayKTestDir("replay-ktest-dir",
                 cl::desc("Specify a directory to replay ktest files from"),
                 cl::value_desc("output directory"),
                 cl::cat(ReplayCat));

  cl::opt<std::string>
  ReplayPathFile("replay-path",
                 cl::desc("Specify a path file to replay"),
                 cl::value_desc("path file"),
                 cl::cat(ReplayCat));



  cl::list<std::string>
  SeedOutFile("seed-file",
              cl::desc(".ktest file to be used as seed"),
              cl::cat(SeedingCat));

  cl::list<std::string>
  SeedOutDir("seed-dir",
             cl::desc("Directory with .ktest files to be used as seeds"),
             cl::cat(SeedingCat));

  cl::opt<unsigned>
  MakeConcreteSymbolic("make-concrete-symbolic",
                       cl::desc("Probabilistic rate at which to make concrete reads symbolic, "
				"i.e. approximately 1 in n concrete reads will be made symbolic (0=off, 1=all).  "
				"Used for testing (default=0)"),
                       cl::init(0),
                       cl::cat(DebugCat));

  cl::opt<unsigned>
  MaxTests("max-tests",
           cl::desc("Stop execution after generating the given number of tests. Extra tests corresponding to partially explored paths will also be dumped.  Set to 0 to disable (default=0)"),
           cl::init(0),
           cl::cat(TerminationCat));

  cl::opt<bool>
  Watchdog("watchdog",
           cl::desc("Use a watchdog process to enforce --max-time (default=false)"),
           cl::init(false),
           cl::cat(TerminationCat));

  cl::opt<bool>
  Libcxx("libcxx",
           cl::desc("Link the llvm libc++ library into the bitcode (default=false)"),
           cl::init(false),
           cl::cat(LinkCat));
  
  cl::list<std::string>
  PerryFunctionHooks("perry-function-hook",
                     cl::desc("Functions to hook"),
                     cl::cat(MiscCat));
}

namespace klee {
extern cl::opt<std::string> MaxTime;
class ExecutionState;
PerryEthInfo *perry_eth_info = nullptr;
PerryTimerInfo *perry_timer_info = nullptr;
PerryDMAInfo *perry_dma_info = nullptr;
}

/***/

class KleeHandler : public InterpreterHandler {
private:
  Interpreter *m_interpreter;
  TreeStreamWriter *m_pathWriter, *m_symPathWriter;
  std::unique_ptr<llvm::raw_ostream> m_infoFile;

  SmallString<128> m_outputDirectory;

  unsigned m_numTotalTests;     // Number of tests received from the interpreter
  unsigned m_numGeneratedTests; // Number of tests successfully generated
  unsigned m_pathsCompleted; // number of completed paths
  unsigned m_pathsExplored; // number of partially explored and completed paths

  // used for writing .ktest files
  int m_argc;
  char **m_argv;

public:
  KleeHandler(int argc, char **argv);
  ~KleeHandler();

  llvm::raw_ostream &getInfoStream() const { return *m_infoFile; }
  /// Returns the number of test cases successfully generated so far
  unsigned getNumTestCases() { return m_numGeneratedTests; }
  unsigned getNumPathsCompleted() { return m_pathsCompleted; }
  unsigned getNumPathsExplored() { return m_pathsExplored; }
  void incPathsCompleted() { ++m_pathsCompleted; }
  unsigned getPathsCompleted() { return m_pathsCompleted; }
  void incPathsExplored(std::uint32_t num = 1) {
    m_pathsExplored += num; }
  unsigned getPathsExplored() { return m_pathsExplored; }

  void setInterpreter(Interpreter *i);

  void processTestCase(const ExecutionState  &state,
                       const char *errorMessage,
                       const char *errorSuffix);

  std::string getOutputFilename(const std::string &filename);
  std::unique_ptr<llvm::raw_fd_ostream> openOutputFile(const std::string &filename);
  std::string getTestFilename(const std::string &suffix, unsigned id);
  std::unique_ptr<llvm::raw_fd_ostream> openTestFile(const std::string &suffix, unsigned id);

  // load a .path file
  static void loadPathFile(std::string name,
                           std::vector<bool> &buffer);

  static void getKTestFilesInDir(std::string directoryPath,
                                 std::vector<std::string> &results);

  static std::string getRunTimeLibraryPath(const char *argv0);
};

KleeHandler::KleeHandler(int argc, char **argv)
    : m_interpreter(0), m_pathWriter(0), m_symPathWriter(0),
      m_outputDirectory(), m_numTotalTests(0), m_numGeneratedTests(0),
      m_pathsCompleted(0), m_pathsExplored(0), m_argc(argc), m_argv(argv) {

  // create output directory (OutputDir or "klee-out-<i>")
  bool dir_given = OutputDir != "";
  SmallString<128> directory(dir_given ? OutputDir : InputFile);

  if (!dir_given) sys::path::remove_filename(directory);
  if (auto ec = sys::fs::make_absolute(directory)) {
    klee_error("unable to determine absolute path: %s", ec.message().c_str());
  }

  if (dir_given) {
    // OutputDir
    if (mkdir(directory.c_str(), 0775) < 0)
      klee_error("cannot create \"%s\": %s", directory.c_str(), strerror(errno));

    m_outputDirectory = directory;
  } else {
    // "klee-out-<i>"
    int i = 0;
    for (; i <= INT_MAX; ++i) {
      SmallString<128> d(directory);
      llvm::sys::path::append(d, "klee-out-");
      raw_svector_ostream ds(d);
      ds << i;
      // SmallString is always up-to-date, no need to flush. See Support/raw_ostream.h

      // create directory and try to link klee-last
      if (mkdir(d.c_str(), 0775) == 0) {
        m_outputDirectory = d;

        // SmallString<128> klee_last(directory);
        // llvm::sys::path::append(klee_last, "klee-last");

        // if (((unlink(klee_last.c_str()) < 0) && (errno != ENOENT)) ||
        //     symlink(m_outputDirectory.c_str(), klee_last.c_str()) < 0) {

        //   klee_warning("cannot create klee-last symlink: %s", strerror(errno));
        // }

        break;
      }

      // otherwise try again or exit on error
      if (errno != EEXIST)
        klee_error("cannot create \"%s\": %s", m_outputDirectory.c_str(), strerror(errno));
    }
    if (i == INT_MAX && m_outputDirectory.str().equals(""))
        klee_error("cannot create output directory: index out of range");
  }

  klee_message("output directory is \"%s\"", m_outputDirectory.c_str());

  // open warnings.txt
  std::string file_path = getOutputFilename("warnings.txt");
  if ((klee_warning_file = fopen(file_path.c_str(), "w")) == NULL)
    klee_error("cannot open file \"%s\": %s", file_path.c_str(), strerror(errno));

  // open messages.txt
  file_path = getOutputFilename("messages.txt");
  if ((klee_message_file = fopen(file_path.c_str(), "w")) == NULL)
    klee_error("cannot open file \"%s\": %s", file_path.c_str(), strerror(errno));

  // open info
  m_infoFile = openOutputFile("info");
}

KleeHandler::~KleeHandler() {
  delete m_pathWriter;
  delete m_symPathWriter;
  fclose(klee_warning_file);
  fclose(klee_message_file);
  /// :) set pointers to null after they're released
  klee_warning_file = nullptr;
  klee_message_file = nullptr;
}

void KleeHandler::setInterpreter(Interpreter *i) {
  m_interpreter = i;

  if (WritePaths) {
    m_pathWriter = new TreeStreamWriter(getOutputFilename("paths.ts"));
    assert(m_pathWriter->good());
    m_interpreter->setPathWriter(m_pathWriter);
  }

  if (WriteSymPaths) {
    m_symPathWriter = new TreeStreamWriter(getOutputFilename("symPaths.ts"));
    assert(m_symPathWriter->good());
    m_interpreter->setSymbolicPathWriter(m_symPathWriter);
  }
}

std::string KleeHandler::getOutputFilename(const std::string &filename) {
  SmallString<128> path = m_outputDirectory;
  sys::path::append(path,filename);
  return path.c_str();
}

std::unique_ptr<llvm::raw_fd_ostream>
KleeHandler::openOutputFile(const std::string &filename) {
  std::string Error;
  std::string path = getOutputFilename(filename);
  auto f = klee_open_output_file(path, Error);
  if (!f) {
    klee_warning("error opening file \"%s\".  KLEE may have run out of file "
                 "descriptors: try to increase the maximum number of open file "
                 "descriptors by using ulimit (%s).",
                 path.c_str(), Error.c_str());
    return nullptr;
  }
  return f;
}

std::string KleeHandler::getTestFilename(const std::string &suffix, unsigned id) {
  std::stringstream filename;
  filename << "test" << std::setfill('0') << std::setw(6) << id << '.' << suffix;
  return filename.str();
}

std::unique_ptr<llvm::raw_fd_ostream>
KleeHandler::openTestFile(const std::string &suffix, unsigned id) {
  return openOutputFile(getTestFilename(suffix, id));
}


/* Outputs all files (.ktest, .kquery, .cov etc.) describing a test case */
void KleeHandler::processTestCase(const ExecutionState &state,
                                  const char *errorMessage,
                                  const char *errorSuffix) {
  if (!WriteNone) {
    std::vector< std::pair<std::string, std::vector<unsigned char> > > out;
    bool success = m_interpreter->getSymbolicSolution(state, out);

    if (!success)
      klee_warning("unable to get symbolic solution, losing test case");

    const auto start_time = time::getWallTime();

    unsigned id = ++m_numTotalTests;

    if (success) {
      KTest b;
      b.numArgs = m_argc;
      b.args = m_argv;
      b.symArgvs = 0;
      b.symArgvLen = 0;
      b.numObjects = out.size();
      b.objects = new KTestObject[b.numObjects];
      assert(b.objects);
      for (unsigned i=0; i<b.numObjects; i++) {
        KTestObject *o = &b.objects[i];
        o->name = const_cast<char*>(out[i].first.c_str());
        o->numBytes = out[i].second.size();
        o->bytes = new unsigned char[o->numBytes];
        assert(o->bytes);
        std::copy(out[i].second.begin(), out[i].second.end(), o->bytes);
      }

      if (!kTest_toFile(&b, getOutputFilename(getTestFilename("ktest", id)).c_str())) {
        klee_warning("unable to write output test case, losing it");
      } else {
        ++m_numGeneratedTests;
      }

      for (unsigned i=0; i<b.numObjects; i++)
        delete[] b.objects[i].bytes;
      delete[] b.objects;
    }

    if (errorMessage) {
      auto f = openTestFile(errorSuffix, id);
      if (f)
        *f << errorMessage;
    }

    if (m_pathWriter) {
      std::vector<unsigned char> concreteBranches;
      m_pathWriter->readStream(m_interpreter->getPathStreamID(state),
                               concreteBranches);
      auto f = openTestFile("path", id);
      if (f) {
        for (const auto &branch : concreteBranches) {
          *f << branch << '\n';
        }
      }
    }

    if (errorMessage || WriteKQueries) {
      std::string constraints;
      m_interpreter->getConstraintLog(state, constraints,Interpreter::KQUERY);
      auto f = openTestFile("kquery", id);
      if (f)
        *f << constraints;
    }

    if (WriteCVCs) {
      // FIXME: If using Z3 as the core solver the emitted file is actually
      // SMT-LIBv2 not CVC which is a bit confusing
      std::string constraints;
      m_interpreter->getConstraintLog(state, constraints, Interpreter::STP);
      auto f = openTestFile("cvc", id);
      if (f)
        *f << constraints;
    }

    if (WriteSMT2s) {
      std::string constraints;
        m_interpreter->getConstraintLog(state, constraints, Interpreter::SMTLIB2);
        auto f = openTestFile("smt2", id);
        if (f)
          *f << constraints;
    }

    if (m_symPathWriter) {
      std::vector<unsigned char> symbolicBranches;
      m_symPathWriter->readStream(m_interpreter->getSymbolicPathStreamID(state),
                                  symbolicBranches);
      auto f = openTestFile("sym.path", id);
      if (f) {
        for (const auto &branch : symbolicBranches) {
          *f << branch << '\n';
        }
      }
    }

    if (WriteCov) {
      std::map<const std::string*, std::set<unsigned> > cov;
      m_interpreter->getCoveredLines(state, cov);
      auto f = openTestFile("cov", id);
      if (f) {
        for (const auto &entry : cov) {
          for (const auto &line : entry.second) {
            *f << *entry.first << ':' << line << '\n';
          }
        }
      }
    }

    if (m_numGeneratedTests == MaxTests)
      m_interpreter->setHaltExecution(true);

    if (WriteTestInfo) {
      time::Span elapsed_time(time::getWallTime() - start_time);
      auto f = openTestFile("info", id);
      if (f)
        *f << "Time to generate test case: " << elapsed_time << '\n';
    }
  } // if (!WriteNone)

  if (errorMessage && OptExitOnError) {
    m_interpreter->prepareForEarlyExit();
    klee_error("EXITING ON ERROR:\n%s\n", errorMessage);
  }
}

  // load a .path file
void KleeHandler::loadPathFile(std::string name,
                                     std::vector<bool> &buffer) {
  std::ifstream f(name.c_str(), std::ios::in | std::ios::binary);

  if (!f.good())
    assert(0 && "unable to open path file");

  while (f.good()) {
    unsigned value;
    f >> value;
    buffer.push_back(!!value);
    f.get();
  }
}

void KleeHandler::getKTestFilesInDir(std::string directoryPath,
                                     std::vector<std::string> &results) {
  std::error_code ec;
  llvm::sys::fs::directory_iterator i(directoryPath, ec), e;
  for (; i != e && !ec; i.increment(ec)) {
    auto f = i->path();
    if (f.size() >= 6 && f.substr(f.size()-6,f.size()) == ".ktest") {
      results.push_back(f);
    }
  }

  if (ec) {
    llvm::errs() << "ERROR: unable to read output directory: " << directoryPath
                 << ": " << ec.message() << "\n";
    exit(1);
  }
}

std::string KleeHandler::getRunTimeLibraryPath(const char *argv0) {
  // allow specifying the path to the runtime library
  const char *env = getenv("KLEE_RUNTIME_LIBRARY_PATH");
  if (env)
    return std::string(env);

  // Take any function from the execution binary but not main (as not allowed by
  // C++ standard)
  void *MainExecAddr = (void *)(intptr_t)getRunTimeLibraryPath;
  SmallString<128> toolRoot(
      llvm::sys::fs::getMainExecutable(argv0, MainExecAddr)
      );

  // Strip off executable so we have a directory path
  llvm::sys::path::remove_filename(toolRoot);

  SmallString<128> libDir;

  if (strlen( KLEE_INSTALL_BIN_DIR ) != 0 &&
      strlen( KLEE_INSTALL_RUNTIME_DIR ) != 0 &&
      toolRoot.str().endswith( KLEE_INSTALL_BIN_DIR ))
  {
    KLEE_DEBUG_WITH_TYPE("klee_runtime", llvm::dbgs() <<
                         "Using installed KLEE library runtime: ");
    libDir = toolRoot.str().substr(0,
               toolRoot.str().size() - strlen( KLEE_INSTALL_BIN_DIR ));
    llvm::sys::path::append(libDir, KLEE_INSTALL_RUNTIME_DIR);
  }
  else
  {
    KLEE_DEBUG_WITH_TYPE("klee_runtime", llvm::dbgs() <<
                         "Using build directory KLEE library runtime :");
    libDir = KLEE_DIR;
    llvm::sys::path::append(libDir, "runtime/lib");
  }

  KLEE_DEBUG_WITH_TYPE("klee_runtime", llvm::dbgs() <<
                       libDir.c_str() << "\n");
  return libDir.c_str();
}

//===----------------------------------------------------------------------===//
// main Driver function
//

static void parseArguments(int argc, char **argv) {
  cl::SetVersionPrinter(klee::printVersion);
  // This version always reads response files
  cl::ParseCommandLineOptions(argc, argv, " klee\n");
}

static void
preparePOSIX(std::vector<std::unique_ptr<llvm::Module>> &loadedModules,
             llvm::StringRef libCPrefix) {
  // Get the main function from the main module and rename it such that it can
  // be called after the POSIX setup
  Function *mainFn = nullptr;
  for (auto &module : loadedModules) {
    mainFn = module->getFunction(EntryPoint);
    if (mainFn)
      break;
  }

  if (!mainFn)
    klee_error("Entry function '%s' not found in module.", EntryPoint.c_str());
  mainFn->setName("__klee_posix_wrapped_main");

  // Add a definition of the entry function if needed. This is the case if we
  // link against a libc implementation. Preparing for libc linking (i.e.
  // linking with uClibc will expect a main function and rename it to
  // _user_main. We just provide the definition here.
  if (!libCPrefix.empty() && !mainFn->getParent()->getFunction(EntryPoint))
    llvm::Function::Create(mainFn->getFunctionType(),
                           llvm::Function::ExternalLinkage, EntryPoint,
                           mainFn->getParent());

  llvm::Function *wrapper = nullptr;
  for (auto &module : loadedModules) {
    wrapper = module->getFunction("__klee_posix_wrapper");
    if (wrapper)
      break;
  }
  assert(wrapper && "klee_posix_wrapper not found");

  // Rename the POSIX wrapper to prefixed entrypoint, e.g. _user_main as uClibc
  // would expect it or main otherwise
  wrapper->setName(libCPrefix + EntryPoint);
}


// This is a terrible hack until we get some real modeling of the
// system. All we do is check the undefined symbols and warn about
// any "unrecognized" externals and about any obviously unsafe ones.

// Symbols we explicitly support
static const char *modelledExternals[] = {
  "_ZTVN10__cxxabiv117__class_type_infoE",
  "_ZTVN10__cxxabiv120__si_class_type_infoE",
  "_ZTVN10__cxxabiv121__vmi_class_type_infoE",

  // special functions
  "_assert",
  "__assert_fail",
  "__assert_rtn",
  "__errno_location",
  "__error",
  "calloc",
  "_exit",
  "exit",
  "free",
  "abort",
  "klee_abort",
  "klee_assume",
  "klee_check_memory_access",
  "klee_define_fixed_object",
  "klee_get_errno",
  "klee_get_valuef",
  "klee_get_valued",
  "klee_get_valuel",
  "klee_get_valuell",
  "klee_get_value_i32",
  "klee_get_value_i64",
  "klee_get_obj_size",
  "klee_is_symbolic",
  "klee_make_symbolic",
  "klee_mark_global",
  "klee_open_merge",
  "klee_close_merge",
  "klee_prefer_cex",
  "klee_posix_prefer_cex",
  "klee_print_expr",
  "klee_print_range",
  "klee_report_error",
  "klee_set_forking",
  "klee_silent_exit",
  "klee_warning",
  "klee_warning_once",
  "klee_stack_trace",
  "klee_set_taint",
  "klee_set_persist_taint",
  "klee_get_taint_internal",
  "klee_get_return_value",
#ifdef SUPPORT_KLEE_EH_CXX
  "_klee_eh_Unwind_RaiseException_impl",
  "klee_eh_typeid_for",
#endif
  "llvm.dbg.declare",
  "llvm.dbg.value",
  "llvm.va_start",
  "llvm.va_end",
  "malloc",
  "realloc",
  "memalign",
  "_ZdaPv",
  "_ZdlPv",
  "_Znaj",
  "_Znwj",
  "_Znam",
  "_Znwm",
  "__ubsan_handle_add_overflow",
  "__ubsan_handle_sub_overflow",
  "__ubsan_handle_mul_overflow",
  "__ubsan_handle_divrem_overflow",
  "__ubsan_handle_out_of_bounds",
  "klee_custom_assert",
  "perry_klee_hook",
  "perry_klee_hook_wrapper",
};

// Symbols we aren't going to warn about
static const char *dontCareExternals[] = {
#if 0
  // stdio
  "fprintf",
  "fflush",
  "fopen",
  "fclose",
  "fputs_unlocked",
  "putchar_unlocked",
  "vfprintf",
  "fwrite",
  "puts",
  "printf",
  "stdin",
  "stdout",
  "stderr",
  "_stdio_term",
  "__errno_location",
  "fstat",
#endif

  // static information, pretty ok to return
  "getegid",
  "geteuid",
  "getgid",
  "getuid",
  "getpid",
  "gethostname",
  "getpgrp",
  "getppid",
  "getpagesize",
  "getpriority",
  "getgroups",
  "getdtablesize",
  "getrlimit",
  "getrlimit64",
  "getcwd",
  "getwd",
  "gettimeofday",
  "uname",

  // fp stuff we just don't worry about yet
  "frexp",
  "ldexp",
  "__isnan",
  "__signbit",
};

// Extra symbols we aren't going to warn about with klee-libc
static const char *dontCareKlee[] = {
  "__ctype_b_loc",
  "__ctype_get_mb_cur_max",

  // I/O system calls
  "open",
  "write",
  "read",
  "close",
};

// Extra symbols we aren't going to warn about with uclibc
static const char *dontCareUclibc[] = {
  "__dso_handle",

  // Don't warn about these since we explicitly commented them out of
  // uclibc.
  "printf",
  "vprintf"
};

// Symbols we consider unsafe
static const char *unsafeExternals[] = {
  "fork", // oh lord
  "exec", // heaven help us
  "error", // calls _exit
  "raise", // yeah
  "kill", // mmmhmmm
};

#define NELEMS(array) (sizeof(array)/sizeof(array[0]))
void externalsAndGlobalsCheck(const llvm::Module *m) {
  std::map<std::string, bool> externals;
  std::set<std::string> modelled(modelledExternals,
                                 modelledExternals+NELEMS(modelledExternals));
  std::set<std::string> dontCare(dontCareExternals,
                                 dontCareExternals+NELEMS(dontCareExternals));
  std::set<std::string> unsafe(unsafeExternals,
                               unsafeExternals+NELEMS(unsafeExternals));

  switch (Libc) {
  case LibcType::KleeLibc:
    dontCare.insert(dontCareKlee, dontCareKlee+NELEMS(dontCareKlee));
    break;
  case LibcType::UcLibc:
    dontCare.insert(dontCareUclibc,
                    dontCareUclibc+NELEMS(dontCareUclibc));
    break;
  case LibcType::FreestandingLibc: /* silence compiler warning */
    break;
  case LibcType::NopNotNever:
    break;
  }

  if (WithPOSIXRuntime)
    dontCare.insert("syscall");

  for (Module::const_iterator fnIt = m->begin(), fn_ie = m->end();
       fnIt != fn_ie; ++fnIt) {
    if (fnIt->isDeclaration() && !fnIt->use_empty())
      externals.insert(std::make_pair(fnIt->getName(), false));
    for (Function::const_iterator bbIt = fnIt->begin(), bb_ie = fnIt->end();
         bbIt != bb_ie; ++bbIt) {
      for (BasicBlock::const_iterator it = bbIt->begin(), ie = bbIt->end();
           it != ie; ++it) {
        if (const CallInst *ci = dyn_cast<CallInst>(it)) {
#if LLVM_VERSION_CODE >= LLVM_VERSION(8, 0)
          if (isa<InlineAsm>(ci->getCalledOperand())) {
#else
          if (isa<InlineAsm>(ci->getCalledValue())) {
#endif
            klee_warning_once(&*fnIt,
                              "function \"%s\" has inline asm",
                              fnIt->getName().data());
          }
        }
      }
    }
  }

  for (Module::const_global_iterator
         it = m->global_begin(), ie = m->global_end();
       it != ie; ++it)
    if (it->isDeclaration() && !it->use_empty())
      externals.insert(std::make_pair(it->getName(), true));
  // and remove aliases (they define the symbol after global
  // initialization)
  for (Module::const_alias_iterator
         it = m->alias_begin(), ie = m->alias_end();
       it != ie; ++it) {
    std::map<std::string, bool>::iterator it2 =
        externals.find(it->getName().str());
    if (it2!=externals.end())
      externals.erase(it2);
  }

  std::map<std::string, bool> foundUnsafe;
  for (std::map<std::string, bool>::iterator
         it = externals.begin(), ie = externals.end();
       it != ie; ++it) {
    const std::string &ext = it->first;
    if (!modelled.count(ext) && (WarnAllExternals ||
                                 !dontCare.count(ext))) {
      if (ext.compare(0, 5, "llvm.") != 0) { // not an LLVM reserved name
        if (unsafe.count(ext)) {
          foundUnsafe.insert(*it);
        } else {
          klee_warning("undefined reference to %s: %s",
                       it->second ? "variable" : "function",
                       ext.c_str());
        }
      }
    }
  }

  for (std::map<std::string, bool>::iterator
         it = foundUnsafe.begin(), ie = foundUnsafe.end();
       it != ie; ++it) {
    const std::string &ext = it->first;
    klee_warning("undefined reference to %s: %s (UNSAFE)!",
                 it->second ? "variable" : "function",
                 ext.c_str());
  }
}

static Interpreter *theInterpreter = 0;

static bool interrupted = false;

// Pulled out so it can be easily called from a debugger.
extern "C"
void halt_execution() {
  theInterpreter->setHaltExecution(true);
}

extern "C"
void stop_forking() {
  theInterpreter->setInhibitForking(true);
}

static void interrupt_handle() {
  if (!interrupted && theInterpreter) {
    llvm::errs() << "KLEE: ctrl-c detected, requesting interpreter to halt.\n";
    halt_execution();
    sys::SetInterruptFunction(interrupt_handle);
  } else {
    llvm::errs() << "KLEE: ctrl-c detected, exiting.\n";
    exit(1);
  }
  interrupted = true;
}

static void interrupt_handle_watchdog() {
  // just wait for the child to finish
}

static void replaceOrRenameFunction(llvm::Module *module,
		const char *old_name, const char *new_name)
{
  Function *new_function, *old_function;
  new_function = module->getFunction(new_name);
  old_function = module->getFunction(old_name);
  if (old_function) {
    if (new_function) {
      old_function->replaceAllUsesWith(new_function);
      old_function->eraseFromParent();
    } else {
      old_function->setName(new_name);
      assert(old_function->getName() == new_name);
    }
  }
}

static void
createLibCWrapper(std::vector<std::unique_ptr<llvm::Module>> &modules,
                  llvm::StringRef intendedFunction,
                  llvm::StringRef libcMainFunction) {
  // XXX we need to rearchitect so this can also be used with
  // programs externally linked with libc implementation.

  // We now need to swap things so that libcMainFunction is the entry
  // point, in such a way that the arguments are passed to
  // libcMainFunction correctly. We do this by renaming the user main
  // and generating a stub function to call intendedFunction. There is
  // also an implicit cooperation in that runFunctionAsMain sets up
  // the environment arguments to what a libc expects (following
  // argv), since it does not explicitly take an envp argument.
  auto &ctx = modules[0]->getContext();
  Function *userMainFn = modules[0]->getFunction(intendedFunction);
  assert(userMainFn && "unable to get user main");
  // Rename entry point using a prefix
  userMainFn->setName("__user_" + intendedFunction);

  // force import of libcMainFunction
  llvm::Function *libcMainFn = nullptr;
  for (auto &module : modules) {
    if ((libcMainFn = module->getFunction(libcMainFunction)))
      break;
  }
  if (!libcMainFn)
    klee_error("Could not add %s wrapper", libcMainFunction.str().c_str());

  auto inModuleReference = libcMainFn->getParent()->getOrInsertFunction(
      userMainFn->getName(), userMainFn->getFunctionType());

  const auto ft = libcMainFn->getFunctionType();

  if (ft->getNumParams() != 7)
    klee_error("Imported %s wrapper does not have the correct "
               "number of arguments",
               libcMainFunction.str().c_str());

  std::vector<Type *> fArgs;
  fArgs.push_back(ft->getParamType(1)); // argc
  fArgs.push_back(ft->getParamType(2)); // argv
  Function *stub =
      Function::Create(FunctionType::get(Type::getInt32Ty(ctx), fArgs, false),
                       GlobalVariable::ExternalLinkage, intendedFunction,
                       libcMainFn->getParent());
  BasicBlock *bb = BasicBlock::Create(ctx, "entry", stub);
  llvm::IRBuilder<> Builder(bb);

  std::vector<llvm::Value*> args;
  args.push_back(llvm::ConstantExpr::getBitCast(
#if LLVM_VERSION_CODE >= LLVM_VERSION(9, 0)
      cast<llvm::Constant>(inModuleReference.getCallee()),
#else
      inModuleReference,
#endif
      ft->getParamType(0)));
  args.push_back(&*(stub->arg_begin())); // argc
  auto arg_it = stub->arg_begin();
  args.push_back(&*(++arg_it)); // argv
  args.push_back(Constant::getNullValue(ft->getParamType(3))); // app_init
  args.push_back(Constant::getNullValue(ft->getParamType(4))); // app_fini
  args.push_back(Constant::getNullValue(ft->getParamType(5))); // rtld_fini
  args.push_back(Constant::getNullValue(ft->getParamType(6))); // stack_end
  Builder.CreateCall(libcMainFn, args);
  Builder.CreateUnreachable();
}

static void
linkWithUclibc(StringRef libDir, std::string opt_suffix,
               std::vector<std::unique_ptr<llvm::Module>> &modules) {
  LLVMContext &ctx = modules[0]->getContext();

  size_t newModules = modules.size();

  // Ensure that klee-uclibc exists
  SmallString<128> uclibcBCA(libDir);
  std::string errorMsg;
  llvm::sys::path::append(uclibcBCA, KLEE_UCLIBC_BCA_NAME);
  if (!klee::loadFile(uclibcBCA.c_str(), ctx, modules, errorMsg))
    klee_error("Cannot find klee-uclibc '%s': %s", uclibcBCA.c_str(),
               errorMsg.c_str());

  for (auto i = newModules, j = modules.size(); i < j; ++i) {
    replaceOrRenameFunction(modules[i].get(), "__libc_open", "open");
    replaceOrRenameFunction(modules[i].get(), "__libc_fcntl", "fcntl");
  }

  createLibCWrapper(modules, EntryPoint, "__uClibc_main");
  klee_message("NOTE: Using klee-uclibc : %s", uclibcBCA.c_str());

  // Link the fortified library
  SmallString<128> FortifyPath(libDir);
  llvm::sys::path::append(FortifyPath,
                          "libkleeRuntimeFortify" + opt_suffix + ".bca");
  if (!klee::loadFile(FortifyPath.c_str(), ctx, modules, errorMsg))
    klee_error("error loading the fortify library '%s': %s",
               FortifyPath.c_str(), errorMsg.c_str());
}

struct PerryApiItem {
  std::string FuncName;
  PerryApiItem(const std::string &FuncName) : FuncName(FuncName) {}
  PerryApiItem() = default;
};

struct PerryFuncRetItem {
  std::string FuncName;
  uint64_t SuccVal;
  PerryFuncRetItem(const std::string &FuncName, uint64_t SuccVal)
    : FuncName(FuncName), SuccVal(SuccVal) {}
  PerryFuncRetItem() = default;
};

template<>
struct llvm::yaml::MappingTraits<PerryApiItem> {
  static void mapping(IO &io, PerryApiItem &item) {
    io.mapRequired("api", item.FuncName);
  }
};

template<>
struct llvm::yaml::MappingTraits<PerryFuncRetItem> {
  static void mapping(IO &io, PerryFuncRetItem &item) {
    io.mapRequired("func", item.FuncName);
    io.mapRequired("succ_val", item.SuccVal);
  }
};

template<>
struct llvm::yaml::SequenceTraits<std::vector<PerryFuncRetItem>> {
  static size_t size(IO &io, std::vector<PerryFuncRetItem> &vec) {
    return vec.size();
  }

  static PerryFuncRetItem &element(IO &io, std::vector<PerryFuncRetItem> &vec,
                                   size_t index) {
    if (index >= vec.size()) {
      vec.resize(index + 1);
    }
    return vec[index];
  }
};

template<>
struct llvm::yaml::SequenceTraits<std::vector<PerryApiItem>> {
  static size_t size(IO &io, std::vector<PerryApiItem> &vec) {
    return vec.size();
  }

  static PerryApiItem &element(IO &io, std::vector<PerryApiItem> &vec,
                               size_t index) {
    if (index >= vec.size()) {
      vec.resize(index + 1);
    }
    return vec[index];
  }
};

static void 
collectTopLevelFunctions(llvm::Module& MainModule,
                         std::set<std::string> &TopLevelFunctions,
                         std::map<StructOffset, std::set<std::string>> &PtrFunc,
                         std::map<std::string, std::unordered_set<uint64_t>> &OkValuesMap)
{
  // load api file
  bool doAutoAnalyzeApi = false;
  bool doAutoAnalyzeEnum = false;
  if (ApiFile.empty()) {
    klee_warning(
      "API file is not given - fallback to built-in analysis on LLVM-IR");
    doAutoAnalyzeApi = true;
  } else {
    auto Result = llvm::MemoryBuffer::getFile(ApiFile);
    if (bool(Result)) {
      std::vector<PerryApiItem> ReadItem;
      llvm::yaml::Input yin(Result->get()->getMemBufferRef());
      yin >> ReadItem;

      if (bool(yin.error())) {
        std::string err_msg;
        raw_string_ostream OS(err_msg);
        OS << "Failed to read data from " << ApiFile;
        klee_error("%s", err_msg.c_str());
      } else {
        for (auto &RI : ReadItem) {
          TopLevelFunctions.insert(RI.FuncName);
        }
      }
    } else {
      std::string err_msg;
      raw_string_ostream OS(err_msg);
      OS << "Failed to open " << ApiFile 
         << ": " << Result.getError().message();
      klee_error("%s", err_msg.c_str());
    }
  }

  // load succ ret file
  if (SuccRetFile.empty()) {
    klee_warning(
      "Success ret file is not given - fallback to built-in analysis");
    doAutoAnalyzeEnum = true;
  } else {
    auto Result = llvm::MemoryBuffer::getFile(SuccRetFile);
    if (bool(Result)) {
      std::vector<PerryFuncRetItem> ReadItem;
      llvm::yaml::Input yin(Result->get()->getMemBufferRef());
      yin >> ReadItem;

      if (bool(yin.error())) {
        std::string err_msg;
        raw_string_ostream OS(err_msg);
        OS << "Failed to read data from " << SuccRetFile;
        klee_error("%s", err_msg.c_str());
      } else {
        for (auto &RI : ReadItem) {
          OkValuesMap.insert(
            std::make_pair(RI.FuncName,
                             std::unordered_set<uint64_t>{RI.SuccVal}));
        }
      }
    } else {
      std::string err_msg;
      raw_string_ostream OS(err_msg);
      OS << "Failed to open " << SuccRetFile 
         << ": " << Result.getError().message();
      klee_error("%s", err_msg.c_str());
    }
  }

  llvm::legacy::PassManager pm;
  // collect basic informations
  pm.add(new PerryAnalysisPass(TopLevelFunctions, PtrFunc, OkValuesMap,
                               doAutoAnalyzeApi, doAutoAnalyzeEnum));

  pm.run(MainModule);
}

void loadLoopInfo(LoopRangeTy &info) {
  if (LoopFile.empty()) {
    klee_warning(
      "Loop file is not given - fallback to built-in analysis");
    return;
  }
  auto Result = llvm::MemoryBuffer::getFile(LoopFile);
  if (bool(Result)) {
    std::vector<PerryLoopItem> ReadItem;
    llvm::yaml::Input yin(Result->get()->getMemBufferRef());
    yin >> ReadItem;

    if (bool(yin.error())) {
      std::string err_msg;
      raw_string_ostream OS(err_msg);
      OS << "Failed to read data from " << LoopFile;
      klee_error("%s", err_msg.c_str());
    } else {
      for (auto &RI : ReadItem) {
        if (info.find(RI.FilePath) == info.end()) {
          info.insert(
            std::make_pair(
              RI.FilePath,
              std::vector<PerryLoopItemLoc> { PerryLoopItemLoc(RI) }));
        } else {
          info[RI.FilePath].push_back(PerryLoopItemLoc(RI));
        }
      }
    }
  } else {
    std::string err_msg;
    raw_string_ostream OS(err_msg);
    OS << "Failed to open " << LoopFile 
        << ": " << Result.getError().message();
    klee_error("%s", err_msg.c_str());
  }
}

static void setInterpreterOptions(Interpreter::InterpreterOptions &IOpts,
                                  Interpreter::TaintOption::Option TaintOpt,
                                  bool CollectTaintedCondOpt,
                                  unsigned int MakeConcreteSymbolicOpt)
{
  IOpts.TaintOpt = Interpreter::TaintOption(TaintOpt);
  IOpts.CollectTaintedCond = CollectTaintedCondOpt;
  IOpts.MakeConcreteSymbolic = MakeConcreteSymbolicOpt;
}

static void singlerun(std::vector<bool> &replayPath,
                      Interpreter::InterpreterOptions &IOpts,
                      LLVMContext &ctx,
                      Interpreter::ModuleOptions &Opts,
                      KModule *loadedModules,
                      std::string mainFunctionName,
                      TaintSet &ts,
                      std::vector<PerryRecord> &records,
                      PerryExprManager &PEM,
                      const std::unordered_set<llvm::BasicBlock *> &loopExitingBlocks,
                      LoopRangeTy &loopRange,
                      const std::unordered_set<std::string> &FunctionHooks,
                      bool do_bind);

static int workerPID;

static void timeoutHandler(int sig) {
  kill(workerPID, SIGINT);
}

static bool
containsReadTo(const std::string &SymName, const ref<PerryExpr> &PE) {
  std::deque<ref<PerryExpr>> WL;
  WL.push_back(PE);
  while (!WL.empty()) {
    auto E = WL.front();
    WL.pop_front();
    if (auto RE = dyn_cast<PerryReadExpr>(E)) {
      if (RE->Name == SymName) {
        return true;
      }
    }
    unsigned numKids = E->getNumKids();
    for (unsigned i = 0; i < numKids; ++i) {
      WL.push_back(E->getKid(i));
    }
  }
  return false;
}

static bool
containsReadTo(const std::string &SymName, const ref<PerryExpr> &PE, int idx) {
  std::deque<ref<PerryExpr>> WL;
  WL.push_back(PE);
  while (!WL.empty()) {
    auto E = WL.front();
    WL.pop_front();
    if (auto RE = dyn_cast<PerryReadExpr>(E)) {
      if (RE->Name == SymName) {
        PerryConstantExpr *PCE = dyn_cast<PerryConstantExpr>(RE->idx);
        if (PCE && PCE->getAPValue().getZExtValue() == (unsigned)idx) {
          return true;
        }
      }
    }
    unsigned numKids = E->getNumKids();
    for (unsigned i = 0; i < numKids; ++i) {
      WL.push_back(E->getKid(i));
    }
  }
  return false;
}

static void
collectContainedSym(const ref<PerryExpr> &PE, std::set<SymRead> &S,
                    const std::string &blacklist="") {
  std::deque<ref<PerryExpr>> WL;
  WL.push_back(PE);
  while (!WL.empty()) {
    auto E = WL.front();
    WL.pop_front();
    if (auto RE = dyn_cast<PerryReadExpr>(E)) {
      if (auto CE = dyn_cast<PerryConstantExpr>(RE->idx)) {
        if (blacklist.empty() || RE->Name != blacklist) {
          S.insert(SymRead(RE->Name, CE->getAPValue().getZExtValue(), RE->width));
        }
      } else {
        klee_warning("Symbolic idx");
      }
    }
    unsigned numKids = E->getNumKids();
    for (unsigned i = 0; i < numKids; ++i) {
      WL.push_back(E->getKid(i));
    }
  }
}

static bool containsReadRelated(const std::set<SymRead> &SR,
                                std::string SymName,
                                const ref<PerryExpr> &PE)
{
  std::deque<ref<PerryExpr>> WL;
  WL.push_back(PE);
  while (!WL.empty()) {
    auto E = WL.front();
    WL.pop_front();
    if (auto RE = dyn_cast<PerryReadExpr>(E)) {
      if (RE->Name == SymName) {
        return true;
      } else {
        if (auto CE = dyn_cast<PerryConstantExpr>(RE->idx)) {
          if (SR.end() !=
              SR.find(SymRead(RE->Name, CE->getAPValue().getZExtValue(), RE->width)))
          {
            return true;
          }
        }
      }
    }
    unsigned numKids = E->getNumKids();
    for (unsigned i = 0; i < numKids; ++i) {
      WL.push_back(E->getKid(i));
    }
  }
  return false;
}

static bool containsReadRelatedStrict(const std::set<SymRead> &SR,
                                      const ref<PerryExpr> &PE)
{
  std::deque<ref<PerryExpr>> WL;
  WL.push_back(PE);
  while (!WL.empty()) {
    auto E = WL.front();
    WL.pop_front();
    if (auto RE = dyn_cast<PerryReadExpr>(E)) {
      if (auto CE = dyn_cast<PerryConstantExpr>(RE->idx)) {
        if (SR.end() ==
            SR.find(SymRead(RE->Name, CE->getAPValue().getZExtValue(), RE->width)))
        {
          return false;
        }
      }
    }
    unsigned numKids = E->getNumKids();
    for (unsigned i = 0; i < numKids; ++i) {
      WL.push_back(E->getKid(i));
    }
  }
  return true;
}

static bool containsReadRelatedRelaxed(const std::set<SymRead> &SR,
                                       const ref<PerryExpr> &PE)
{
  std::deque<ref<PerryExpr>> WL;
  WL.push_back(PE);
  while (!WL.empty()) {
    auto E = WL.front();
    WL.pop_front();
    if (auto RE = dyn_cast<PerryReadExpr>(E)) {
      if (auto CE = dyn_cast<PerryConstantExpr>(RE->idx)) {
        if (SR.end() !=
            SR.find(SymRead(RE->Name, CE->getAPValue().getZExtValue(), RE->width)))
        {
          return true;
        }
      }
    }
    unsigned numKids = E->getNumKids();
    for (unsigned i = 0; i < numKids; ++i) {
      WL.push_back(E->getKid(i));
    }
  }
  return false;
}

static bool hasSameConstraints(std::vector<ref<PerryExpr>> &a,
                               std::vector<ref<PerryExpr>> &b)
{
  if (a.size() != b.size()) {
    return false;
  }
  auto numExpr = a.size();
  for (size_t i = 0; i < numExpr; ++i) {
    if (a[i]->compare(*b[i])) {
      return false;
    }
  }
  return true;
}

static bool
isUniqueConstraints(std::vector<std::vector<ref<PerryExpr>>> &unique_constraints,
                    std::vector<ref<PerryExpr>> &a)
{
  for (auto &CS : unique_constraints) {
    if (hasSameConstraints(CS, a)) {
      return false;
    }
  }
  unique_constraints.push_back(a);
  return true;
}

// static bool
// containsReadOnlyTO(const ref<PerryExpr> &target, const SymRead &SR) {
//   std::deque<ref<PerryExpr>> WL;
//   WL.push_back(target);
//   while (!WL.empty()) {
//     auto E = WL.front();
//     WL.pop_front();
//     if (E->getKind() == Expr::Read) {
//       auto RE = cast<PerryReadExpr>(E);
//       if (RE->Name != SR.name) {
//         return false;
//       }
//       if (RE->idx->getKind() != Expr::Constant) {
//         return false;
//       }
//       auto REidx = cast<PerryConstantExpr>(RE->idx);
//       SymRead tmpSR(SR.name, REidx->getAPValue().getZExtValue(), RE->getWidth());
//       if (!tmpSR.relatedWith(SR)) {
//         return false;
//       }
//     }
//     unsigned numKids = E->getNumKids();
//     for (unsigned i = 0; i < numKids; ++i) {
//       WL.push_back(E->getKid(i));
//     }
//   }
//   return true;
// }

// check whether `a` and `b` are in nested blocks. `b` is assumed to be in the
// inner layer.
// 1  means yes
// 0  means no
// -1 means don't know
static int inNestedScope(Instruction *a, Instruction *b) {
  // always return 1 when disabled
  if (!EnableScopeHeuristic) {
    return 1;
  }

  if (!a->hasMetadata(LLVMContext::MD_dbg) ||
      !b->hasMetadata(LLVMContext::MD_dbg))
  {
    return -1;
  }

  MDNode *MA = a->getMetadata(LLVMContext::MD_dbg);
  MDNode *MB = b->getMetadata(LLVMContext::MD_dbg);
  DIScope *SA;
  DIScope *SB;
  if (MA->getMetadataID() == Metadata::MetadataKind::DILocationKind) {
    auto DLA = cast<DILocation>(MA);
    SA = DLA->getScope();
  } else {
    std::string tmp;
    raw_string_ostream OS(tmp);
    MA->print(OS);
    klee_error("Cannot handle metadata %s", tmp.c_str());
  }
  if (MB->getMetadataID() == Metadata::MetadataKind::DILocationKind) {
    auto DLB = cast<DILocation>(MB);
    SB = DLB->getScope();
  } else {
    std::string tmp;
    raw_string_ostream OS(tmp);
    MB->print(OS);
    klee_error("Cannot handle metadata %s", tmp.c_str());
  }
  if (SA == nullptr || SB == nullptr) {
    return -1;
  }

  if (a->getParent()->getParent() != b->getParent()->getParent()) {
    // cross function
    return -1;
  }

  SA = SA->getScope();
  SB = SB->getScope();
  if (SA == nullptr || SB == nullptr) {
    return -1;
  }
  if (SA == SB) {
    // NOTE: this is somehow heuristic
    return 0;
  }

  while (SB) {
    if (SA == SB) {
      return 1;
    }
    SB = SB->getScope();
  }
  return 0;
}

// -1: dont know
//  0: not in loop condition
//  1: yes
int inLoopCondition(Instruction *inst, LoopRangeTy &LoopRanges) {
  // static LoopRangeTy _LookUpMap;
  using LoopUpCacheTy
    = std::unordered_map<std::string, std::map<std::pair<unsigned, unsigned>, bool>>;
  static LoopUpCacheTy LookUpCache;

  // LoopRangeTy &LookUpMap = LoopRanges.empty() ? _LookUpMap : LoopRanges;
  LoopRangeTy &LookUpMap = LoopRanges;

  if (!inst->hasMetadata(LLVMContext::MD_dbg)) {
    return -1;
  }
  auto MDN = inst->getMetadata(LLVMContext::MD_dbg);
  if (MDN->getMetadataID() != Metadata::DILocationKind) {
    klee_error("inLoopCondition: unsupported metadata kind");
  }
  auto DILoc = cast<DILocation>(MDN);
  if (DILoc->getInlinedAt()) {
    DILoc = DILoc->getInlinedAt();
  }
  auto read_line = DILoc->getLine();
  auto read_col = DILoc->getColumn();
  auto DScope = DILoc->getScope();
  unsigned block_line, block_line_end;
  unsigned block_col, block_col_end;

  auto DIF = DScope->getFile();
  if (!DIF) {
    return -1;
  }
  auto file_path = (DIF->getDirectory() + "/" + DIF->getFilename()).str();
  llvm::SmallString<128> real_path;
  std::error_code err_code = sys::fs::real_path(file_path, real_path);
  if (err_code) {
    klee_error("err when translate %s to real path", file_path.c_str());
  }
  file_path = real_path.str().str();
  // check cache to see if we have issued the same query
  auto read_pair = std::make_pair(read_line, read_col);
  auto c_it = LookUpCache.find(file_path);
  if (c_it != LookUpCache.end()) {
    auto e_it = c_it->second.find(read_pair);
    if (e_it != c_it->second.end()) {
      if (e_it->second) {
        return 1;
      } else {
        return 0;
      }
    }
  } else {
    LookUpCache.insert(
      std::make_pair(file_path, std::map<std::pair<unsigned, unsigned>, bool>()));
  }

  // then check existing ranges
  if (LookUpMap.find(file_path) != LookUpMap.end()) {
    for (auto &p : LookUpMap[file_path]) {
      if (p.contains(read_line, read_col)) {
        LookUpCache[file_path].insert(std::make_pair(read_pair, true));
        return 1;
      }
    }
    if (!LoopFile.empty()) {
      LookUpCache[file_path].insert(std::make_pair(read_pair, false));
      return 0;
    }
  } else {
    if (!LoopFile.empty()) {
      LookUpCache[file_path].insert(std::make_pair(read_pair, false));
      return 0;
    }
    // init the entry, only executed when the loop file is not given
    LookUpMap.insert(std::make_pair(file_path, std::vector<PerryLoopItemLoc>()));
  }

  // fallback: parse the source code, only executed when the loop file is not given
  block_line = read_line;
  block_col = 0;    // read the whole line

  std::ifstream src_file(file_path);
  if (src_file.is_open()) {
    std::string line;
    unsigned cur_line_no = 0;
    while (std::getline(src_file, line)) {
      ++cur_line_no;
      if (cur_line_no == block_line) {
        break;
      }
    }
    std::size_t while_pos;
    auto tmp_col = block_col;
    while (true) {
      while_pos = line.find("while", tmp_col);
      if (while_pos == std::string::npos) {
        LookUpCache[file_path].insert(std::make_pair(read_pair, false));
        return 0;
      }
      if (while_pos > 0) {
        if (!isspace(line[while_pos - 1])) {
          if (isalnum(line[while_pos - 1]) || line[while_pos - 1] == '_') {
            tmp_col = while_pos + 5;
            continue;
          }
        }
      }
      if (while_pos + 5 < line.size() - 1) {
        if (!isspace(line[while_pos + 5])) {
          if (isalnum(line[while_pos + 5]) || line[while_pos + 5] == '_') {
            tmp_col = while_pos + 5;
            continue;
          }
        }
      }
      break;
    }
    while_pos += 5;
    block_col = while_pos;
    auto line_size = line.size();
    std::stack<int> parenthesis;
    while (while_pos < line_size) {
      char cur_char = line[while_pos];
      if (cur_char == '(') {
        parenthesis.push(0);
      } else if (cur_char == ')') {
        parenthesis.pop();
        if (parenthesis.empty()) {
          block_col_end = while_pos;
          break;
        }
      }
      ++while_pos;
    }
    block_line_end = block_line;
    if (!parenthesis.empty()) {
      // we need to read more
      while (true) {
        std::string next_line;
        if (std::getline(src_file, next_line)) {
          ++block_line_end;
          unsigned next_line_size = next_line.size();
          unsigned ii;
          for (ii = 0; ii < next_line_size; ++ii) {
            char this_char = next_line[ii];
            if (this_char == '(') {
              parenthesis.push(0);
            } else if (this_char == ')') {
              parenthesis.pop();
              if (parenthesis.empty()) {
                block_col_end = ii;
                break;
              }
            }
          }
          if (parenthesis.empty()) {
            break;
          }
        } else {
          klee_error("should not happen");
        }
      }
    }
    block_col += 1;
    block_col_end += 1;
    PerryLoopItemLoc new_loc_item(block_line, block_col,
                                  block_line_end, block_col_end);
    LookUpMap[file_path].push_back(new_loc_item);
    if (new_loc_item.contains(read_line, read_col)) {
      LookUpCache[file_path].insert(std::make_pair(read_pair, true));
      return 1;
    } else {
      LookUpCache[file_path].insert(std::make_pair(read_pair, false));
      return 0;
    }
  } else {
    klee_error("cannot open src file %s", file_path.c_str());
  }
}

// find the index of the last common expr of `of` and 'in' in `in`
// return value:
// -1: no match
// else: index in `in`
static int findLastIn(const PerryTrace::Constraints &of,
                      const PerryTrace::Constraints &in)
{
  unsigned of_size = of.size();
  unsigned in_size = in.size();
  if (of_size == 0 || in_size == 0) {
    return 0;
  }
  for (unsigned i = of_size; i > 0; --i) {
    auto &of_expr = of[i - 1];
    for (unsigned j = in_size; j > 0; --j) {
      auto &in_expr = in[j - 1];
      if (of_expr == in_expr) {
        return j;
      }
    }
  }
  return -1;
}

static bool contains(const std::vector<ref<PerryExpr>> &a,
                     const ref<PerryExpr> &b) {
  std::deque<ref<PerryExpr>> WL;
  for (auto &e : a) {
    WL.push_back(e);
  }
  while (!WL.empty()) {
    auto cur = WL.front();
    WL.pop_front();
    if (cur == b) {
      return true;
    } else {
      unsigned num_kids = cur->getNumKids();
      for (unsigned i = 0; i < num_kids; ++i) {
        WL.push_back(cur->getKid(i));
      }
    }
  }
  return false;
}

static void
inferWRDependence(const PerryTrace::PerryTraceItem &PTI,
                  const PerryTrace::PerryTraceItem &last_PTI,
                  const std::vector<ref<RegisterAccess>> &reg_accesses,
                  const std::vector<ref<PerryExpr>> &constraint_to_use,
                  const PerryTrace &trace, int i,
                  PerryDependentMap &wrDepMap,
                  const std::string &PeriphSymName) {
  auto &last_access = reg_accesses[last_PTI.reg_access_idx];
  auto &cur_access = reg_accesses[PTI.reg_access_idx];
  unsigned num_cs = PTI.cur_constraints.size();
  unsigned num_constraint_on_read
    = constraint_to_use.size();
  auto this_result = cur_access->ExprInReg;
  std::set<SymRead> after_syms;
  std::set<SymRead> add_syms;
  collectContainedSym(this_result, after_syms);
  collectContainedSym(this_result, add_syms, PeriphSymName);
  std::vector<ref<PerryExpr>> after_constraints;
  std::vector<ref<PerryExpr>> after_constraints_added;
  int this_idx = findLastIn(PTI.cur_constraints,
                            constraint_to_use);
  assert(this_idx != -1);
  // collect remaining constraint
  for (unsigned j = this_idx; j < num_constraint_on_read; ++j) {
    if (containsReadRelated(after_syms, "", constraint_to_use[j])) {
      after_constraints.push_back(constraint_to_use[j]);
      collectContainedSym(constraint_to_use[j], add_syms, PeriphSymName);
    }
  }
  for (unsigned j = 0; j < (unsigned)this_idx; ++j) {
    if (containsReadRelatedStrict(add_syms, constraint_to_use[j])) {
      after_constraints.push_back(constraint_to_use[j]);
      after_constraints_added.push_back(constraint_to_use[j]);
    }
  }
  if (!after_constraints.empty()) {
    // collect constraints on the written expression till this read, if any
    auto last_result = last_access->ExprInReg;
    std::set<SymRead> before_syms;
    collectContainedSym(last_result, before_syms);
    std::vector<ref<PerryExpr>> before_constraints;
    for (unsigned j = 0; j < num_cs; ++j) {
      if (containsReadRelated(before_syms, "", PTI.cur_constraints[j])) {
        before_constraints.push_back(PTI.cur_constraints[j]);
      }
    }
    DependentItemKey key(
      SymRead(cur_access->name,
              cur_access->offset,
              cur_access->width),
      this_result, after_constraints);
    key.constraints_added = after_constraints_added;
    if (wrDepMap.find(key) == wrDepMap.end()) {
      wrDepMap.insert(
        std::make_pair(key, std::set<DependentItemVal>()));
    }
    // locate last write/read to this reg
    SymRead written_reg = SymRead(last_access->name,
                                  last_access->offset,
                                  last_access->width);
    ref<PerryExpr> before_expr = 0;
    SymRead cur_reg(written_reg);
    for (int j = i - 2; j >= 0; --j) {
      auto &cur_PTI = trace[j];
      auto &tmp_access = reg_accesses[cur_PTI.reg_access_idx];
      cur_reg = SymRead(tmp_access->name,
                        tmp_access->offset,
                        tmp_access->width);
      if (cur_reg.relatedWith(written_reg)) {
        before_expr = tmp_access->ExprInReg;
        break;
      }
    }
    DependentItemVal val(
      written_reg, before_expr, last_result, before_constraints);
    if (before_expr) {
      val.before_sym = cur_reg;
    }
    wrDepMap.at(key).insert(val);
  }
}

static void
inferRRDependence(const PerryTrace::PerryTraceItem &PTI,
                  const PerryTrace::PerryTraceItem &last_PTI,
                  const std::vector<ref<RegisterAccess>> &reg_accesses,
                  const std::vector<ref<PerryExpr>> &final_constraints,
                  const PerryTrace &trace, unsigned i,
                  PerryDependentMap &rrDepMap) {
  auto &last_access = reg_accesses[last_PTI.reg_access_idx];
  auto &cur_access = reg_accesses[PTI.reg_access_idx];
  auto last_result = last_access->ExprInReg;
  unsigned trace_size = trace.size();
  unsigned num_cs = PTI.cur_constraints.size();
  std::vector<ref<PerryExpr>> before_constraints,
                              after_constraints;
  std::set<SymRead> before_syms;
  collectContainedSym(last_result, before_syms);
  // look-before to find related constraints
  int this_idx = findLastIn(last_PTI.cur_constraints,
                            PTI.cur_constraints);
  assert(this_idx != -1);
  for (unsigned j = this_idx; j < num_cs; ++j) {
    if (containsReadRelated(before_syms, "", PTI.cur_constraints[j])) {
      before_constraints.push_back(PTI.cur_constraints[j]);
    }
  }
  if (!before_constraints.empty()) {
    // now we have a potential dependent pair
    // look-after to find the constraint this read must meet to 
    // successfully return
    auto &constraint_to_use
      = (i == trace_size - 1) ? final_constraints
                              : trace[i + 1].cur_constraints;
    unsigned num_constraint_on_read
      = constraint_to_use.size();
    auto this_result = cur_access->ExprInReg;
    std::set<SymRead> after_syms;
    collectContainedSym(this_result, after_syms);
    this_idx = findLastIn(PTI.cur_constraints, constraint_to_use);
    assert(this_idx != -1);
    for (unsigned j = this_idx; j < num_constraint_on_read; ++j) {
      if (containsReadRelated(after_syms, "", constraint_to_use[j])) {
        after_constraints.push_back(constraint_to_use[j]);
      }
    }
    if (!after_constraints.empty()) {
      DependentItemKey key(
        SymRead(cur_access->name,
                cur_access->offset,
                cur_access->width),
        this_result, after_constraints);
      if (rrDepMap.find(key) == rrDepMap.end()) {
        rrDepMap.insert(
          std::make_pair(key, std::set<DependentItemVal>()));
      }
      ref<PerryExpr> before_expr = 0;
      SymRead read_reg(last_access->name,
                        last_access->offset,
                        last_access->width);
      SymRead cur_reg(read_reg);
      for (int j = i - 2; j >= 0; --j) {
        auto &cur_PTI = trace[j];
        auto &tmp_access = reg_accesses[cur_PTI.reg_access_idx];
        cur_reg = SymRead(tmp_access->name,
                          tmp_access->offset,
                          tmp_access->width);
        if (cur_reg.relatedWith(read_reg)) {
          before_expr = tmp_access->ExprInReg;
          break;
        }
      }
      DependentItemVal val(
        read_reg, before_expr, last_result, before_constraints);
      if (before_expr) {
        val.before_sym = cur_reg;
      }
      rrDepMap.at(key).insert(val);
    }
  }
}

static void
inferWRDependenceWithCheckPoint(const PerryCheckPoint &cp,
                                const std::vector<ref<RegisterAccess>> &reg_accesses,
                                const PerryTrace &trace,
                                PerryDependentMap &wrDepMap,
                                LoopRangeTy &LoopRanges,
                                const std::string &PeriphSymName) {
  unsigned reg_access_size = cp.reg_access_size;
  auto &cur_access = reg_accesses[reg_access_size - 1];
  auto &last_access = reg_accesses[reg_access_size - 2];

  if (inLoopCondition(cur_access->place, LoopRanges) <= 0) {
    return;
  }

  auto &last_result = last_access->ExprInReg;
  auto &this_result = cur_access->ExprInReg;
  std::vector<ref<PerryExpr>> after_constraints;
  std::vector<ref<PerryExpr>> after_constraints_added;
  auto &cs_to_use = cp.constraints;
  unsigned num_cs = cs_to_use.size();

  after_constraints.push_back(cp.condition);
  std::set<SymRead> add_syms;
  collectContainedSym(this_result, add_syms, PeriphSymName);
  collectContainedSym(cp.condition, add_syms, PeriphSymName);
  for (unsigned j = 0; j < num_cs; ++j) {
    if (containsReadRelatedStrict(add_syms, cs_to_use[j])) {
      after_constraints.push_back(cs_to_use[j]);
      after_constraints_added.push_back(cs_to_use[j]);
    }
  }

  std::set<SymRead> before_syms;
  collectContainedSym(last_result, before_syms);
  std::vector<ref<PerryExpr>> before_constraints;

  for (unsigned j = 0; j < num_cs; ++j) {
    if (containsReadRelated(before_syms, "", cs_to_use[j])) {
      before_constraints.push_back(cs_to_use[j]);
    }
  }
  DependentItemKey key(
    SymRead(cur_access->name,
            cur_access->offset,
            cur_access->width),
    this_result, after_constraints);
  key.constraints_added = after_constraints_added;
  if (wrDepMap.find(key) == wrDepMap.end()) {
    wrDepMap.insert(
      std::make_pair(key, std::set<DependentItemVal>()));
  }
  // locate last write/read to this reg
  SymRead written_reg = SymRead(last_access->name,
                                last_access->offset,
                                last_access->width);
  ref<PerryExpr> before_expr = 0;
  SymRead cur_reg(written_reg);
  if (reg_access_size > 2) {
    for (int j = reg_access_size - 3; j >= 0; --j) {
      auto &cur_PTI = trace[j];
      auto &tmp_access = reg_accesses[cur_PTI.reg_access_idx];
      cur_reg = SymRead(tmp_access->name,
                        tmp_access->offset,
                        tmp_access->width);
      if (cur_reg.relatedWith(written_reg)) {
        before_expr = tmp_access->ExprInReg;
        break;
      }
    }
  }
  DependentItemVal val(
    written_reg, before_expr, last_result, before_constraints);
  if (before_expr) {
    val.before_sym = cur_reg;
  }
  wrDepMap.at(key).insert(val);
}

static void
inferRRDependenceWithCheckPoint(const PerryCheckPoint &cp,
                                const std::vector<ref<RegisterAccess>> &reg_accesses,
                                const PerryTrace &trace,
                                PerryDependentMap &rrDepMap,
                                ControlDependenceGraphPass::NodeMap &nm,
                                LoopRangeTy &LoopRanges) {
  unsigned reg_access_size = cp.reg_access_size;
  auto &cur_access = reg_accesses[reg_access_size - 1];
  auto &last_access = reg_accesses[reg_access_size - 2];

  int depend_on_prev
    = ControlDependenceGraphPass::
      isControlDependentOn(nm, cur_access->place->getParent(),
                               last_access->place->getParent());
  if (!(inLoopCondition(cur_access->place, LoopRanges) > 0 &&
      depend_on_prev == 1 &&
      inNestedScope(last_access->place, cur_access->place))) {
    return;
  }

  auto &PTI = trace[reg_access_size - 1];
  auto &last_PTI = trace[reg_access_size - 2];
  unsigned num_cs = PTI.cur_constraints.size();
  std::vector<ref<PerryExpr>> before_constraints,
                              after_constraints;
  auto &last_result = last_access->ExprInReg;
  std::set<SymRead> before_syms;
  collectContainedSym(last_result, before_syms);
  int this_idx = findLastIn(last_PTI.cur_constraints, PTI.cur_constraints);
  assert(this_idx != -1);
  for (unsigned j = this_idx; j < num_cs; ++j) {
    if (containsReadRelated(before_syms, "", PTI.cur_constraints[j])) {
      before_constraints.push_back(PTI.cur_constraints[j]);
    }
  }
  if (before_constraints.empty()) {
    return;
  }
  auto &this_result = cur_access->ExprInReg;
  after_constraints.push_back(cp.condition);
  DependentItemKey key(
    SymRead(cur_access->name,
            cur_access->offset,
            cur_access->width),
            this_result, after_constraints);
  if (rrDepMap.find(key) == rrDepMap.end()) {
    rrDepMap.insert(
      std::make_pair(key, std::set<DependentItemVal>()));
  }
  ref<PerryExpr> before_expr = 0;
  SymRead read_reg(last_access->name,
                   last_access->offset,
                   last_access->width);
  SymRead cur_reg(read_reg);
  for (int j = reg_access_size - 3; j >= 0; --j) {
    auto &cur_PTI = trace[j];
    auto &tmp_access = reg_accesses[cur_PTI.reg_access_idx];
    cur_reg = SymRead(tmp_access->name,
                      tmp_access->offset,
                      tmp_access->width);
    if (cur_reg.relatedWith(read_reg)) {
      before_expr = tmp_access->ExprInReg;
      break;
    }
  }
  DependentItemVal val(
    read_reg, before_expr, last_result, before_constraints);
  if (before_expr) {
    val.before_sym = cur_reg;
  }
  rrDepMap.at(key).insert(val);
}

static const std::vector<std::string> timer_enable_funcs = {
  "LL_TIM_EnableCounter",
  "LL_LPTIM_Enable",
};

static const std::vector<std::string> timer_disable_funcs = {
  "LL_TIM_DisableCounter"
};

static const std::set<std::string> timer_irq_funcs = {
  "HAL_TIM_PeriodElapsedCallback",
};

static const std::vector<std::string> dma_enable_funcs = {
  "LL_DMA_EnableChannel",
  "LL_DMA_EnableStream",
};

static const std::vector<std::string> dma_disable_funcs = {
  "LL_DMA_DisableChannel",
  "LL_DMA_DisableStream"
};

static const std::vector<std::string> dma_rx_enable_funcs = {
  "LL_USART_EnableDMAReq_RX",
  "LL_I2C_EnableDMAReq_RX",
  "LL_SPI_EnableDMAReq_RX",
  "LL_I2S_EnableDMAReq_RX",
};

static const std::vector<std::string> dma_rx_disable_funcs = {
  "LL_USART_DisableDMAReq_RX",
  "LL_I2C_DisableDMAReq_RX",
  "LL_SPI_DisableDMAReq_RX",
  "LL_I2S_DisableDMAReq_RX",
};

static const std::vector<std::string> dma_tx_enable_funcs = {
  "LL_USART_EnableDMAReq_TX",
  "LL_I2C_EnableDMAReq_TX",
  "LL_SPI_EnableDMAReq_TX",
  "LL_I2S_EnableDMAReq_TX",
};

static const std::vector<std::string> dma_tx_disable_funcs = {
  "LL_USART_DisableDMAReq_TX",
  "LL_I2C_DisableDMAReq_TX",
  "LL_SPI_DisableDMAReq_TX",
  "LL_I2S_DisableDMAReq_TX",
};

static const std::set<std::string> general_irq_hooks = {
  "HAL_UARTEx_RxEventCallback",
  "UART_EndTransmit_IT",
  "HAL_ADC_ConvCpltCallback",
  "HAL_ADCEx_InjectedConvCpltCallback",
  "HAL_ADC_LevelOutOfWindowCallback",
  "HAL_GPIO_EXTI_Callback",
};

static void
postProcess(const std::set<std::string> &TopLevelFunctions,
            const std::map<std::string, std::string> &FunctionToSymbolName,
            const std::map<std::string, std::vector<PerryRecord>> &allRecords,
            const TaintSet &liveTaint,
            const std::map<std::string, std::unordered_set<uint64_t>> &OkValuesMap,
            ControlDependenceGraphPass::NodeMap &nm,
            LoopRangeTy &LoopRanges)
{
  TaintSet byReg;
  for (auto t : liveTaint) {
    addTaint(byReg, getRegTaint(t));
  }
  std::cerr << "Possible data registers offsets: ";
  for (auto t : byReg) {
    std::cerr << t << ", ";
  }
  std::cerr << "\n";

  std::vector<std::vector<ref<PerryExpr>>> unique_constraints_read,
                                           unique_constraints_write,
                                           unique_constraints_irq,
                                           unique_constraints_between_writes;
  std::vector<std::vector<std::vector<ref<PerryExpr>>>> unique_constraints_final_per_function;
  std::set<unsigned> writtenDataRegIdx, readDataRegIdx;
  PerryDependentMap rrDepMap, wrDepMap;

  bool isIRQ = false;
  PerryZ3Builder z3builder;
  z3::expr_vector timer_enable_conds(z3builder.getContext());
  z3::expr_vector timer_disable_conds(z3builder.getContext());
  z3::expr_vector dma_enable_conds(z3builder.getContext());
  z3::expr_vector dma_disable_conds(z3builder.getContext());
  z3::expr_vector dma_rx_enable_conds(z3builder.getContext());
  z3::expr_vector dma_rx_disable_conds(z3builder.getContext());
  z3::expr_vector dma_tx_enable_conds(z3builder.getContext());
  z3::expr_vector dma_tx_disable_conds(z3builder.getContext());
  std::vector<std::vector<ref<PerryExpr>>> timer_irq_conds;
  std::vector<std::vector<std::vector<ref<PerryExpr>>>> dma_xfer_cplt_irq_conds(32);
  std::map<std::tuple<unsigned, unsigned, unsigned>, z3::expr> final_src_dst;

  for (auto TopFunc : TopLevelFunctions) {
    assert(FunctionToSymbolName.find(TopFunc) != FunctionToSymbolName.end());
    isIRQ = (TopFunc.find("IRQHandler") != std::string::npos);
    auto SymName = FunctionToSymbolName.at(TopFunc);
    auto &Record = allRecords.at(TopFunc);
    const std::unordered_set<uint64_t> *OkVals = nullptr;
    if (OkValuesMap.find(TopFunc) != OkValuesMap.end()) {
      OkVals = &OkValuesMap.at(TopFunc);
    }
    unique_constraints_final_per_function.push_back(std::vector<std::vector<ref<PerryExpr>>>());

    if (!perry_dma_info->src_symbol.empty() &&
        perry_dma_info->src_symbol.find(TopFunc) != perry_dma_info->src_symbol.end()) {
      for (auto &rec : Record) {
        auto &trace = rec.trace;
        auto &reg_accesses = rec.register_accesses;
        for (auto &PTI : trace) {
          auto &cur_access = reg_accesses[PTI.reg_access_idx];
          if (cur_access->AccessType != RegisterAccess::REG_WRITE) {
            continue;
          }
          if (containsReadTo(perry_dma_info->src_symbol[TopFunc].sym,
                             cur_access->ExprInReg,
                             perry_dma_info->src_symbol[TopFunc].idx)) {
            perry_dma_info->src_reg_idx.insert(cur_access->offset);
          }
        }
      }
    }

    if (!perry_dma_info->dst_symbol.empty() &&
        perry_dma_info->dst_symbol.find(TopFunc) != perry_dma_info->dst_symbol.end()) {
      for (auto &rec : Record) {
        auto &trace = rec.trace;
        auto &reg_accesses = rec.register_accesses;
        for (auto &PTI : trace) {
          auto &cur_access = reg_accesses[PTI.reg_access_idx];
          if (cur_access->AccessType != RegisterAccess::REG_WRITE) {
            continue;
          }
          if (containsReadTo(perry_dma_info->dst_symbol[TopFunc].sym,
                             cur_access->ExprInReg,
                             perry_dma_info->dst_symbol[TopFunc].idx)) {
            perry_dma_info->dst_reg_idx.insert(cur_access->offset);
          }
        }
      }
    }

    if (!perry_dma_info->cnt_symbol.empty() &&
        perry_dma_info->cnt_symbol.find(TopFunc) != perry_dma_info->cnt_symbol.end()) {
      for (auto &rec : Record) {
        auto &trace = rec.trace;
        auto &reg_accesses = rec.register_accesses;
        for (auto &PTI : trace) {
          auto &cur_access = reg_accesses[PTI.reg_access_idx];
          if (cur_access->AccessType != RegisterAccess::REG_WRITE) {
            continue;
          }
          if (containsReadTo(perry_dma_info->cnt_symbol[TopFunc].sym,
                             cur_access->ExprInReg,
                             perry_dma_info->cnt_symbol[TopFunc].idx)) {
            perry_dma_info->cnt_reg_idx.insert(cur_access->offset);
          }
        }
      }
    }

    if (isIRQ) {
      for (auto &rec : Record) {
        for (auto &hk : rec.triggerred_hooks) {
          if (!StringRef(hk.hook_name).startswith(PERRY_DMA_XFER_CPLT_HOOK)) {
            continue;
          }
          unsigned cidx = 0;
          if (hk.hook_name.size() > strlen(PERRY_DMA_XFER_CPLT_HOOK)) {
            cidx = std::stoul(hk.hook_name.substr(strlen(PERRY_DMA_XFER_CPLT_HOOK)));
          }
          auto &cs_cur = hk.constraints;
          std::vector<ref<PerryExpr>> DMAXferCpltIRQConstraint;
          for (auto &CS : cs_cur) {
            if (containsReadTo(SymName, CS)) {
              DMAXferCpltIRQConstraint.push_back(CS);
            }
          }
          isUniqueConstraints(dma_xfer_cplt_irq_conds[cidx], DMAXferCpltIRQConstraint);
        }
      }
    }

    bool should_continue = false;

    for (auto &def : dma_enable_funcs) {
      if (def == TopFunc) {
        for (auto &rec : Record) {
          auto &trace = rec.trace;
          auto &reg_accesses = rec.register_accesses;
          for (auto &PTI : trace) {
            auto &cur_access = reg_accesses[PTI.reg_access_idx];
            if (cur_access->AccessType != RegisterAccess::REG_WRITE) {
              continue;
            }
            z3::expr_vector bit_level_expr(z3builder.getContext());
            z3::expr_vector empty_blacklist(z3builder.getContext());
            z3builder.getBitLevelExpr(cur_access->ExprInReg, bit_level_expr);
            SymRead sr(cur_access->name, cur_access->offset, cur_access->width);
            auto bit_constraints
              = z3builder.inferBitLevelConstraintWithBlacklist(
                  z3builder.getContext().bool_val(true), sr,
                  empty_blacklist, bit_level_expr);
            bit_constraints = bit_constraints.simplify();
            dma_enable_conds.push_back(bit_constraints);
          }
        }
        should_continue = true;
        break;
      }
    }

    if (should_continue) {
      continue;
    }

    for (auto &ddf : dma_disable_funcs) {
      if (ddf == TopFunc) {
        for (auto &rec : Record) {
          auto &trace = rec.trace;
          auto &reg_accesses = rec.register_accesses;
          for (auto &PTI : trace) {
            auto &cur_access = reg_accesses[PTI.reg_access_idx];
            if (cur_access->AccessType != RegisterAccess::REG_WRITE) {
              continue;
            }
            z3::expr_vector bit_level_expr(z3builder.getContext());
            z3::expr_vector empty_blacklist(z3builder.getContext());
            z3builder.getBitLevelExpr(cur_access->ExprInReg, bit_level_expr);
            SymRead sr(cur_access->name, cur_access->offset, cur_access->width);
            auto bit_constraints
              = z3builder.inferBitLevelConstraintWithBlacklist(
                  z3builder.getContext().bool_val(true), sr,
                  empty_blacklist, bit_level_expr);
            bit_constraints = bit_constraints.simplify();
            dma_disable_conds.push_back(bit_constraints);
          }
        }
        should_continue = true;
        break;
      }
    }

    if (should_continue) {
      continue;
    }

    for (auto &dre : dma_rx_enable_funcs) {
      if (dre == TopFunc) {
        for (auto &rec : Record) {
          auto &trace = rec.trace;
          auto &reg_accesses = rec.register_accesses;
          for (auto &PTI : trace) {
            auto &cur_access = reg_accesses[PTI.reg_access_idx];
            if (cur_access->AccessType != RegisterAccess::REG_WRITE) {
              continue;
            }
            z3::expr_vector bit_level_expr(z3builder.getContext());
            z3::expr_vector empty_blacklist(z3builder.getContext());
            z3builder.getBitLevelExpr(cur_access->ExprInReg, bit_level_expr);
            SymRead sr(cur_access->name, cur_access->offset, cur_access->width);
            auto bit_constraints
              = z3builder.inferBitLevelConstraintWithBlacklist(
                  z3builder.getContext().bool_val(true), sr,
                  empty_blacklist, bit_level_expr);
            bit_constraints = bit_constraints.simplify();
            dma_rx_enable_conds.push_back(bit_constraints);
          }
        }
        should_continue = true;
        break;
      }
    }

    if (should_continue) {
      continue;
    }

    for (auto &ddf : dma_rx_disable_funcs) {
      if (ddf == TopFunc) {
        for (auto &rec : Record) {
          auto &trace = rec.trace;
          auto &reg_accesses = rec.register_accesses;
          for (auto &PTI : trace) {
            auto &cur_access = reg_accesses[PTI.reg_access_idx];
            if (cur_access->AccessType != RegisterAccess::REG_WRITE) {
              continue;
            }
            z3::expr_vector bit_level_expr(z3builder.getContext());
            z3::expr_vector empty_blacklist(z3builder.getContext());
            z3builder.getBitLevelExpr(cur_access->ExprInReg, bit_level_expr);
            SymRead sr(cur_access->name, cur_access->offset, cur_access->width);
            auto bit_constraints
              = z3builder.inferBitLevelConstraintWithBlacklist(
                  z3builder.getContext().bool_val(true), sr,
                  empty_blacklist, bit_level_expr);
            bit_constraints = bit_constraints.simplify();
            dma_rx_disable_conds.push_back(bit_constraints);
          }
        }
        should_continue = true;
        break;
      }
    }

    if (should_continue) {
      continue;
    }

    for (auto &ddf : dma_tx_enable_funcs) {
      if (ddf == TopFunc) {
        for (auto &rec : Record) {
          auto &trace = rec.trace;
          auto &reg_accesses = rec.register_accesses;
          for (auto &PTI : trace) {
            auto &cur_access = reg_accesses[PTI.reg_access_idx];
            if (cur_access->AccessType != RegisterAccess::REG_WRITE) {
              continue;
            }
            z3::expr_vector bit_level_expr(z3builder.getContext());
            z3::expr_vector empty_blacklist(z3builder.getContext());
            z3builder.getBitLevelExpr(cur_access->ExprInReg, bit_level_expr);
            SymRead sr(cur_access->name, cur_access->offset, cur_access->width);
            auto bit_constraints
              = z3builder.inferBitLevelConstraintWithBlacklist(
                  z3builder.getContext().bool_val(true), sr,
                  empty_blacklist, bit_level_expr);
            bit_constraints = bit_constraints.simplify();
            dma_tx_enable_conds.push_back(bit_constraints);
          }
        }
        should_continue = true;
        break;
      }
    }

    if (should_continue) {
      continue;
    }

    for (auto &ddf : dma_tx_disable_funcs) {
      if (ddf == TopFunc) {
        for (auto &rec : Record) {
          auto &trace = rec.trace;
          auto &reg_accesses = rec.register_accesses;
          for (auto &PTI : trace) {
            auto &cur_access = reg_accesses[PTI.reg_access_idx];
            if (cur_access->AccessType != RegisterAccess::REG_WRITE) {
              continue;
            }
            z3::expr_vector bit_level_expr(z3builder.getContext());
            z3::expr_vector empty_blacklist(z3builder.getContext());
            z3builder.getBitLevelExpr(cur_access->ExprInReg, bit_level_expr);
            SymRead sr(cur_access->name, cur_access->offset, cur_access->width);
            auto bit_constraints
              = z3builder.inferBitLevelConstraintWithBlacklist(
                  z3builder.getContext().bool_val(true), sr,
                  empty_blacklist, bit_level_expr);
            bit_constraints = bit_constraints.simplify();
            dma_tx_disable_conds.push_back(bit_constraints);
          }
        }
        should_continue = true;
        break;
      }
    }

    if (should_continue) {
      continue;
    }
    
    for (auto &tef : timer_enable_funcs) {
      if (tef == TopFunc) {
        for (auto &rec : Record) {
          auto &trace = rec.trace;
          auto &reg_accesses = rec.register_accesses;
          for (auto &PTI : trace) {
            auto &cur_access = reg_accesses[PTI.reg_access_idx];
            if (cur_access->AccessType != RegisterAccess::REG_WRITE) {
              continue;
            }
            z3::expr_vector bit_level_expr(z3builder.getContext());
            z3::expr_vector empty_blacklist(z3builder.getContext());
            z3builder.getBitLevelExpr(cur_access->ExprInReg, bit_level_expr);
            SymRead sr(cur_access->name, cur_access->offset, cur_access->width);
            auto bit_constraints
              = z3builder.inferBitLevelConstraintWithBlacklist(
                  z3builder.getContext().bool_val(true), sr,
                  empty_blacklist, bit_level_expr);
            bit_constraints = bit_constraints.simplify();
            timer_enable_conds.push_back(bit_constraints);
          }
        }
        should_continue = true;
        break;
      }
    }

    if (should_continue) {
      continue;
    }

    for (auto &tdf : timer_disable_funcs) {
      if (tdf == TopFunc) {
        for (auto &rec : Record) {
          auto &trace = rec.trace;
          auto &reg_accesses = rec.register_accesses;
          for (auto &PTI : trace) {
            auto &cur_access = reg_accesses[PTI.reg_access_idx];
            if (cur_access->AccessType != RegisterAccess::REG_WRITE) {
              continue;
            }
            z3::expr_vector bit_level_expr(z3builder.getContext());
            z3::expr_vector empty_blacklist(z3builder.getContext());
            z3builder.getBitLevelExpr(cur_access->ExprInReg, bit_level_expr);
            SymRead sr(cur_access->name, cur_access->offset, cur_access->width);
            auto bit_constraints
              = z3builder.inferBitLevelConstraintWithBlacklist(
                  z3builder.getContext().bool_val(true), sr,
                  empty_blacklist, bit_level_expr);
            bit_constraints = bit_constraints.simplify();
            timer_disable_conds.push_back(bit_constraints);
          }
        }
        should_continue = true;
        break;
      }
    }

    if (should_continue) {
      continue;
    }

    if (isIRQ) {
      for (auto &rec : Record) {
        for (auto &hk : rec.triggerred_hooks) {
          if (timer_irq_funcs.find(hk.hook_name) != timer_irq_funcs.end()) {
            auto &cs_cur = hk.constraints;
            std::vector<ref<PerryExpr>> TimerIRQConstraint;
            for (auto &CS : cs_cur) {
              if (containsReadTo(SymName, CS)) {
                TimerIRQConstraint.push_back(CS);
              }
            }
            isUniqueConstraints(timer_irq_conds, TimerIRQConstraint);
            should_continue = true;
          }

          if (general_irq_hooks.find(hk.hook_name) != general_irq_hooks.end()) {
            auto &cs_cur = hk.constraints;
            std::vector<ref<PerryExpr>> GeneralIRQConstraints;
            for (auto &CS : cs_cur) {
              if (containsReadTo(SymName, CS)) {
                GeneralIRQConstraints.push_back(CS);
              }
            }
            if (!GeneralIRQConstraints.empty()) {
              isUniqueConstraints(unique_constraints_irq, GeneralIRQConstraints);
            }
            should_continue = false;
          }

          if (hk.hook_name == PERRY_GENERAL_HOOK) {
            auto &cs_cur = hk.constraints;
            std::vector<ref<PerryExpr>> GeneralIRQConstraints;
            for (auto &CS : cs_cur) {
              if (containsReadTo(SymName, CS)) {
                GeneralIRQConstraints.push_back(CS);
              }
            }
            if (!GeneralIRQConstraints.empty()) {
              isUniqueConstraints(unique_constraints_irq, GeneralIRQConstraints);
            }
            should_continue = false;
          }
        }
      }
    }

    if (should_continue) {
      continue;
    }

    if (!byReg.empty() && StringRef(TopFunc).startswith("LL_")) {
      continue;
    }

    // for (auto &TR : Trace) {
    for (auto &rec : Record) {
      // single state
      auto &trace = rec.trace;
      auto &final_constraints = rec.final_constraints;
      auto returned_value = rec.return_value;
      auto &reg_accesses = rec.register_accesses;
      auto success_return = rec.success;
      auto &checkpoints = rec.checkpoints;
      std::vector<ref<PerryExpr>> lastWriteConstraint;
      unsigned last_write_idx = 0;
      bool hasWrite = false;
      bool hasNonDataRead = false;
      for (auto &PTI : trace) {
        auto &cur_access = reg_accesses[PTI.reg_access_idx];
        if (cur_access->AccessType == RegisterAccess::REG_READ) {
          // not a data register
          if (byReg.find(getRegTaint(cur_access->idx)) == byReg.end()) {
            hasNonDataRead = true;
            continue;
          }
          // is a data register, but the read has no taint
          auto &ts = trace.getTaintSet();
          if (ts.find(cur_access->idx) == ts.end()) {
            continue;
          }
        } else {
          // write to non-data registers are ignored
          if (byReg.find(getRegTaint(cur_access->idx)) == byReg.end()) {
            continue;
          }
        }

        std::vector<ref<PerryExpr>> RegConstraint;
        auto &cs_cur = PTI.cur_constraints;
        for (auto &CS : cs_cur) {
          if (containsReadTo(SymName, CS)) {
            RegConstraint.push_back(CS);
          }
        }
        
        if (cur_access->AccessType == RegisterAccess::REG_READ) {
          readDataRegIdx.insert(cur_access->offset);
          for (auto &CP : checkpoints) {
            if (PTI.reg_access_idx >= CP.reg_access_size_post) {
              RegConstraint.push_back(CP.condition);
            }
          }
          if (isIRQ) {
            isUniqueConstraints(unique_constraints_irq, RegConstraint);
          }
          isUniqueConstraints(unique_constraints_read, RegConstraint);
        } else {
          writtenDataRegIdx.insert(cur_access->offset);
          hasWrite = true;
          if (!lastWriteConstraint.empty()) {
            // diff
            unsigned lastSize = lastWriteConstraint.size();
            unsigned thisSize = RegConstraint.size();

            std::vector<ref<PerryExpr>> diffExpr;
            for (unsigned i = lastSize; i < thisSize; ++i) {
              diffExpr.push_back(RegConstraint[i]);
            }
            for (auto &CP : checkpoints) {
              if (last_write_idx < CP.reg_access_size && PTI.reg_access_idx >= CP.reg_access_size_post) {
                diffExpr.push_back(CP.condition);
              }
            }
            if (!diffExpr.empty()) {
              (void)
              isUniqueConstraints(unique_constraints_between_writes, diffExpr);
            }
          }
          lastWriteConstraint = RegConstraint;
          last_write_idx = PTI.reg_access_idx;
          for (auto &CP : checkpoints) {
            if (PTI.reg_access_idx >= CP.reg_access_size_post) {
              RegConstraint.push_back(CP.condition);
            }
          }
          if (isIRQ) {
            isUniqueConstraints(unique_constraints_irq, RegConstraint);
          }
          isUniqueConstraints(unique_constraints_write, RegConstraint);
        }
      }

      if (success_return && (
          (OkVals && OkVals->find(returned_value) != OkVals->end()) ||
          !OkVals)) {
        // normal exit
        // data register writes
        if (hasWrite && !isIRQ) {
          std::vector<ref<PerryExpr>> finalCS;
          for (auto &CS : final_constraints) {
            if (containsReadTo(SymName, CS)) {
              finalCS.push_back(CS);
            }
          }
          unsigned finalSize = finalCS.size();
          std::vector<ref<PerryExpr>> diffFinalCS;
          for (unsigned i = lastWriteConstraint.size(); i < finalSize; ++i) {
            diffFinalCS.push_back(finalCS[i]);
          }
          for (auto &CP : checkpoints) {
            if (last_write_idx < CP.reg_access_size) {
              diffFinalCS.push_back(CP.condition);
            }
          }
          unique_constraints_final_per_function.back().push_back(diffFinalCS);
        }

        // dependent non-data register reads
        if (hasNonDataRead) {
          // infer reg linkage
          // case 1: two adjacent in-constraint reads
          // case 2: a in-constraint read and previous writes
          bool last_is_read = false;
          bool last_is_data = false;

          unsigned trace_size = trace.size();
          for (unsigned i = 0; i < trace_size; ++i) {
            auto &PTI = trace[i];
            // unsigned num_cs = PTI.cur_constraints.size();
            auto &cur_access = reg_accesses[PTI.reg_access_idx];

            // skip data register accesses
            if (readDataRegIdx.find(cur_access->offset) != readDataRegIdx.end()) {
              last_is_read = false;
              last_is_data = true;
              continue;
            }

            if (cur_access->AccessType == RegisterAccess::REG_READ) {
              if (last_is_read) {
                // two adjacent reads, and new constraints are introduced.
                // check whether the newly-introduced constraints contains
                // the result of the previous read.
                auto &last_PTI = trace[i - 1];
                auto &last_access = reg_accesses[last_PTI.reg_access_idx];
                int depend_on_prev 
                  = ControlDependenceGraphPass::isControlDependentOn(
                    nm, cur_access->place->getParent(),
                        last_access->place->getParent());
                
                if (inLoopCondition(cur_access->place, LoopRanges) > 0 &&
                    depend_on_prev == 1 && 
                    inNestedScope(last_access->place, cur_access->place)) {
                  bool blacklisted = false;
                  for (auto &cp : checkpoints) {
                    if (PTI.reg_access_idx == cp.reg_access_size - 1) {
                      blacklisted = true;
                      break;
                    }
                  }
                  if (!blacklisted) {
                    inferRRDependence(PTI, last_PTI, reg_accesses,
                                      final_constraints, trace, i, rrDepMap);
                  }
                }
              } else if (!last_is_read && i > 0 && !last_is_data) {
                if (inLoopCondition(cur_access->place, LoopRanges) > 0) {
                  bool blacklisted = false;
                  for (auto &cp : checkpoints) {
                    if (PTI.reg_access_idx == cp.reg_access_size - 1) {
                      blacklisted = true;
                      break;
                    }
                  }
                  if (!blacklisted) {
                    auto &last_PTI = trace[i - 1];
                    // auto &last_access = reg_accesses[last_PTI.reg_access_idx];
                    auto &constraint_to_use
                      = (i == trace_size - 1) ? final_constraints
                                              : trace[i + 1].cur_constraints;
                    inferWRDependence(PTI, last_PTI, reg_accesses,
                                      constraint_to_use, trace, i, wrDepMap, SymName);
                  }
                }
              }
              last_is_read = true;
            } else {
              last_is_read = false;
            }
            last_is_data = false;
          }

          // deal with checkpoints
          for (auto &cp : checkpoints) {
            unsigned reg_access_size = cp.reg_access_size;
            if (reg_access_size < 2) {
              continue;
            }
            auto &cur_access = reg_accesses[reg_access_size - 1];
            if (cur_access->AccessType != RegisterAccess::REG_READ) {
              continue;
            }
            if (readDataRegIdx.find(cur_access->offset) != readDataRegIdx.end()) {
              continue;
            }
            auto &last_access = reg_accesses[reg_access_size - 2];

            if (last_access->AccessType == RegisterAccess::REG_READ) {
              if (readDataRegIdx.find(last_access->offset) != readDataRegIdx.end()) {
                continue;
              }
              inferRRDependenceWithCheckPoint(cp, reg_accesses, trace,
                                              rrDepMap, nm, LoopRanges);
            } else if (last_access->AccessType == RegisterAccess::REG_WRITE){
              if (writtenDataRegIdx.find(last_access->offset) != writtenDataRegIdx.end()) {
                continue;
              }
              inferWRDependenceWithCheckPoint(cp, reg_accesses, trace,
                                              wrDepMap, LoopRanges, SymName);
            }
          }
        }
      }
    }
  }

  if (!perry_dma_info->src_reg_idx.empty()) {
    // try resolve direction if src and dst registers overlap
    bool overlap = false;
    for (auto sr : perry_dma_info->src_reg_idx) {
      if (perry_dma_info->dst_reg_idx.find(sr) == perry_dma_info->dst_reg_idx.end()) {
        continue;
      }
      overlap = true;
      break;
    }
    if (overlap) {
      // determine the condition
      std::map<std::tuple<unsigned, unsigned, unsigned>, z3::expr_vector> src_dst;
      for (auto TopFunc : TopLevelFunctions) {
        auto SymName = FunctionToSymbolName.at(TopFunc);
        auto &Record = allRecords.at(TopFunc);

        if (perry_dma_info->src_symbol.find(TopFunc) != perry_dma_info->src_symbol.end()) {
          for (auto &rec : Record) {
            auto &trace = rec.trace;
            auto &reg_accesses = rec.register_accesses;
            unsigned src_reg;
            unsigned dst_reg;
            unsigned cnt_reg;
            bool found_dir = false;
            bool found_src = false;
            bool found_dst = false;
            bool found_cnt = false;
            z3::expr the_cs = z3builder.getContext().bool_val(true);
            for (auto &PTI : trace) {
              auto &cur_access = reg_accesses[PTI.reg_access_idx];
              if (cur_access->AccessType != RegisterAccess::REG_WRITE) {
                continue;
              }
              if (containsReadTo(perry_dma_info->src_symbol[TopFunc].sym,
                                cur_access->ExprInReg,
                                perry_dma_info->src_symbol[TopFunc].idx)) {
                src_reg = cur_access->offset;
                found_src = true;
                std::set<SymRead> contained_syms;
                for (auto &cccsss : PTI.cur_constraints) {
                  collectContainedSym(cccsss, contained_syms, SymName);
                }
                for (auto &PPTI : trace) {
                  if (&PPTI == &PTI) {
                    break;
                  }
                  auto &cur_acc = reg_accesses[PPTI.reg_access_idx];
                  if (cur_acc->AccessType != RegisterAccess::REG_WRITE) {
                    continue;
                  }
                  if (!containsReadRelatedRelaxed(contained_syms, cur_acc->ExprInReg)) {
                    continue;
                  }
                  found_dir = true;
                  z3::expr_vector bit_level_expr(z3builder.getContext());
                  z3::expr_vector empty_blacklist(z3builder.getContext());
                  z3builder.getBitLevelExpr(cur_acc->ExprInReg, bit_level_expr);
                  SymRead sr(cur_acc->name, cur_acc->offset, cur_acc->width);
                  auto cur_cs = z3builder.toZ3ExprAnd(PTI.cur_constraints);
                  auto bit_constraints
                    = z3builder.inferBitLevelConstraintWithBlacklist(
                        cur_cs, sr, empty_blacklist, bit_level_expr);
                  the_cs = bit_constraints.simplify();
                  break;
                }
              }
            }
            if (found_dir && found_src) {
              for (auto &PTI : trace) {
                auto &cur_access = reg_accesses[PTI.reg_access_idx];
                if (cur_access->AccessType != RegisterAccess::REG_WRITE) {
                  continue;
                }
                if (containsReadTo(perry_dma_info->dst_symbol[TopFunc].sym,
                                    cur_access->ExprInReg,
                                    perry_dma_info->dst_symbol[TopFunc].idx)) {
                  dst_reg = cur_access->offset;
                  found_dst = true;
                  break;
                }
              }
            }

            if (found_dir && found_dst && found_src) {
              for (auto &PTI : trace) {
                auto &cur_access = reg_accesses[PTI.reg_access_idx];
                if (cur_access->AccessType != RegisterAccess::REG_WRITE) {
                  continue;
                }
                if (containsReadTo(perry_dma_info->cnt_symbol[TopFunc].sym,
                                   cur_access->ExprInReg,
                                   perry_dma_info->cnt_symbol[TopFunc].idx)) {
                  cnt_reg = cur_access->offset;
                  found_cnt = true;
                  break;
                }
              }
              if (found_cnt) {
                auto src_dst_cnt_tuple = std::make_tuple(src_reg, dst_reg, cnt_reg);
                if (src_dst.find(src_dst_cnt_tuple) == src_dst.end()) {
                  src_dst.insert(
                    std::make_pair(src_dst_cnt_tuple, z3::expr_vector(z3builder.getContext())));
                }
                src_dst.at(src_dst_cnt_tuple).push_back(the_cs);
              }
            }
          }
        }
      }

      std::map<std::tuple<unsigned, unsigned, unsigned>, z3::expr> simplified_src_dst;
      for (auto &ent : src_dst) {
        auto &all_cs = ent.second;
        z3::expr cs = z3builder.getLogicalBitExprOr(all_cs, false, true);
        simplified_src_dst.insert(std::make_pair(ent.first, cs));
      }

      // find non-overlap conditions, if any
      std::set<std::tuple<unsigned, unsigned, unsigned>> visited_src_dst;
      for (auto &ent : simplified_src_dst) {
        if (visited_src_dst.find(ent.first) == visited_src_dst.end()) {
          visited_src_dst.insert(ent.first);
          auto mirror_pair = std::make_tuple(
            std::get<1>(ent.first), std::get<0>(ent.first), std::get<2>(ent.first));
          visited_src_dst.insert(mirror_pair);
          auto it = simplified_src_dst.find(mirror_pair);
          assert(it != simplified_src_dst.end());
          z3::expr this_cs = ent.second;
          z3::expr mirror_cs = it->second;
          if (this_cs.is_and() && mirror_cs.is_and()) {
            // extract non-overlapping conditions
            auto this_args = this_cs.args();
            auto mirror_args = mirror_cs.args();
            unsigned num_this_args = this_args.size();
            unsigned num_mirror_args = mirror_args.size();
            if (num_this_args != num_mirror_args) {
              auto more_args = num_this_args >= num_mirror_args ? this_args : mirror_args;
              auto less_args = num_this_args >= num_mirror_args ? mirror_args : this_args;
              z3::expr_vector diff_args(z3builder.getContext());
              z3::solver s(z3builder.getContext());
              for (const auto &ma : more_args) {
                bool found_same_expr = false;
                for (const auto &la : less_args) {
                  s.reset();
                  s.add(ma != la);
                  auto res = s.check();
                  if (res == z3::unsat) {
                    found_same_expr = true;
                    break;
                  }
                }
                if (!found_same_expr) {
                  diff_args.push_back(ma);
                }
              }
              z3::expr real_cond = diff_args.size() == 1 ? diff_args[0] : z3::mk_and(diff_args);
              z3::expr neg_real_cond = !real_cond;
              real_cond = real_cond.simplify();
              neg_real_cond = neg_real_cond.simplify();
              if (num_this_args >= num_mirror_args) {
                final_src_dst.insert(std::make_pair(ent.first, real_cond));
                final_src_dst.insert(std::make_pair(mirror_pair, neg_real_cond));
              } else {
                final_src_dst.insert(std::make_pair(ent.first, neg_real_cond));
                final_src_dst.insert(std::make_pair(mirror_pair, real_cond));
              }
              continue;
            }
          }
          final_src_dst.insert(std::make_pair(ent.first, this_cs));
          final_src_dst.insert(std::make_pair(mirror_pair, mirror_cs));
        }
      }
    } else {
      std::vector<unsigned> src_regs(
        perry_dma_info->src_reg_idx.begin(), perry_dma_info->src_reg_idx.end());
      std::vector<unsigned> dst_regs(
        perry_dma_info->dst_reg_idx.begin(), perry_dma_info->dst_reg_idx.end());
      std::vector<unsigned> cnt_regs(
        perry_dma_info->cnt_reg_idx.begin(), perry_dma_info->cnt_reg_idx.end());
      std::sort(cnt_regs.begin(), cnt_regs.end());
      std::sort(src_regs.begin(), src_regs.end());
      std::sort(dst_regs.begin(), dst_regs.end());
      unsigned num_regs = src_regs.size();
      assert(src_regs.size() == dst_regs.size());
      for (unsigned i = 0; i < num_regs; ++i) {
        final_src_dst.insert(
          std::make_pair(
            std::make_tuple(src_regs[i], dst_regs[i], cnt_regs[i]),
            z3builder.getContext().bool_val(true)));
      }
    }
  }

  // deal with read-read dependences
  // the logic is: if some constraints on the value read from the first register
  // is satisfied, some other constraints must be met on the second register
  std::map<unsigned, unsigned> rr_expr_id_to_idx;
  z3::expr_vector rr_conds(z3builder.getContext());
  z3::expr_vector rr_actions_final(z3builder.getContext());
  std::vector<z3::expr_vector> rr_actions;
  for (auto &key : rrDepMap) {
    // errs() << "rr##############################\n";
    // errs() << key.first << "----------------------------\n";
    std::set<SymRead> keySyms;
    collectContainedSym(key.first.expr, keySyms);
    auto key_cs = z3builder.getLogicalBitExprAnd(key.first.constraints, "",
                                                 false, keySyms, true);
    z3::expr_vector bit_level_expr_key(z3builder.getContext());
    z3builder.getBitLevelExpr(key.first.expr, bit_level_expr_key);
    auto bit_constraints_key
      = z3builder.inferBitLevelConstraint(key_cs, key.first.sym,
                                          bit_level_expr_key);
    bit_constraints_key = bit_constraints_key.simplify();
    for (auto &val : key.second) {
      std::set<SymRead> fuckSyms;
      collectContainedSym(val.after, fuckSyms);
      auto wis = z3builder.getLogicalBitExprAnd(val.constraints, "",
                                                false, fuckSyms, true);
      // z3::expr_vector bit_level_expr_before(z3builder.getContext());
      z3::expr_vector bit_level_expr_after(z3builder.getContext());
      // if (val.before) {
      //   z3builder.getBitLevelExpr(val.before, bit_level_expr_before);
      // }
      z3builder.getBitLevelExpr(val.after, bit_level_expr_after);
      // auto blacklist
      //   = z3builder.inferBitLevelConstraintRaw(wis, val.before_sym,
      //                                          bit_level_expr_before);
      auto bit_constraints_after
        = z3builder.inferBitLevelConstraint(wis, val.sym, bit_level_expr_after);
      bit_constraints_after = bit_constraints_after.simplify();
      if (rr_expr_id_to_idx.find(bit_constraints_after.id())
          == rr_expr_id_to_idx.end())
      {
        rr_expr_id_to_idx.insert(std::make_pair(bit_constraints_after.id(),
                                                rr_conds.size()));
        rr_conds.push_back(bit_constraints_after);
        rr_actions.push_back(z3::expr_vector(z3builder.getContext()));
      }
      auto cur_idx = rr_expr_id_to_idx[bit_constraints_after.id()];
      rr_actions[cur_idx].push_back(bit_constraints_key);
    }
  }

  // deal with write-read dependences
  // the logic is: if some constraints on the written value is satisfied, some
  // other constraints must be met on the register to be read
  std::map<unsigned, unsigned> wr_expr_id_to_idx;
  z3::expr_vector wr_conds(z3builder.getContext());
  std::vector<z3::expr_vector> wr_actions;
  for (auto &key : wrDepMap) {
    // errs() << "wr##############################\n";
    // errs() << key.first << "----------------------------\n";
    std::set<SymRead> keySyms;
    collectContainedSym(key.first.expr, keySyms);
    auto key_cs = z3builder.getLogicalBitExprAnd(key.first.constraints, "",
                                                 false, keySyms, true);
    z3::expr_vector bit_level_expr_key(z3builder.getContext());
    z3builder.getBitLevelExpr(key.first.expr, bit_level_expr_key);
    auto bit_constraints_key
      = z3builder.inferBitLevelConstraint(key_cs, key.first.sym,
                                          bit_level_expr_key);
    bit_constraints_key = bit_constraints_key.simplify();
    z3::expr_vector val_constraints(z3builder.getContext());
    for (auto &val : key.second) {
      if (!val.constraints.empty()) {
        // there're constraints on the written value
        // errs() << val << "...................................\n";
        std::set<SymRead> fuckSyms;
        collectContainedSym(val.after, fuckSyms);
        auto wis = z3builder.getLogicalBitExprAnd(val.constraints, "",
                                                  false, fuckSyms, true);
        z3::expr_vector bit_level_expr_before(z3builder.getContext());
        z3::expr_vector bit_level_expr_after(z3builder.getContext());
        if (val.before) {
          z3builder.getBitLevelExpr(val.before, bit_level_expr_before);
        }
        z3builder.getBitLevelExpr(val.after, bit_level_expr_after);
        auto blacklist
          = z3builder.inferBitLevelConstraintRaw(wis, val.before_sym,
                                                 bit_level_expr_before);
        
        auto bit_constraints_after
          = z3builder.inferBitLevelConstraintWithBlacklist(wis,
                                                           val.sym,
                                                           blacklist,
                                                           bit_level_expr_after);
        val_constraints.push_back(bit_constraints_after);
      } else {
        // no constraint on the written value
        if (val.after->getKind() != Expr::Constant) {
          z3::expr_vector bit_level_expr_after(z3builder.getContext());
          z3::expr_vector bit_level_expr_before(z3builder.getContext());
          if (val.before) {
            z3builder.getBitLevelExpr(val.before, bit_level_expr_before);
          }
          z3builder.getBitLevelExpr(val.after, bit_level_expr_after);
          auto true_cs = z3builder.getContext().bool_val(true);
          auto blacklist
            = z3builder.inferBitLevelConstraintRaw(true_cs,
                                                    val.before_sym,
                                                    bit_level_expr_before);
          
          auto bit_constraints_after
            = z3builder.inferBitLevelConstraintWithBlacklist(true_cs,
                                                              val.sym,
                                                              blacklist,
                                                              bit_level_expr_after);
          val_constraints.push_back(bit_constraints_after);
        } else {
          // the written value is constrained to be this constant
          auto PCE = cast<PerryConstantExpr>(val.after);
          val_constraints.push_back(
            z3builder.getConstantConstraint(val.sym,
                                            PCE->getAPValue().getZExtValue()));
        }
      }
      z3::expr final_val_constraint = val_constraints.back();
      val_constraints.pop_back();
      final_val_constraint = final_val_constraint.simplify();
      bool reset_constraint_key = false;
      if (bit_constraints_key.is_true()) {
        // post constraints are not enough to resolve the constraint on this register
        // this can happen when symbols are compared with symbols.
        // We additionally add constraints on the previously written value and repeat
        // this process. Hopefully this can help.
        z3::expr_vector tmp_vec(z3builder.getContext());
        if (!val.constraints.empty()) {
          std::set<SymRead> tmpSyms;
          collectContainedSym(val.after, tmpSyms);
          auto wis = z3builder.getLogicalBitExprAnd(val.constraints, "",
                                                    false, tmpSyms, true);
          tmp_vec.push_back(wis);
          tmp_vec.push_back(key_cs);
          z3::expr tmp_key_cs = z3::mk_and(tmp_vec);
          tmp_key_cs = tmp_key_cs.simplify();
          z3::expr_vector bit_level_expr_again(bit_level_expr_key);
          // z3builder.getBitLevelExpr(key.first.expr, bit_level_expr_again);
          bit_constraints_key
            = z3builder.inferBitLevelConstraint(tmp_key_cs, key.first.sym,
                                                bit_level_expr_again);
          bit_constraints_key = bit_constraints_key.simplify();
          reset_constraint_key = true;
        }
      }
      if (bit_constraints_key.is_true() && final_val_constraint.is_true()) {
        if (contains(key.first.constraints, val.after)) {
          // Neither the condition nor the action can be inferred, but the action
          // can be expressed using the condition. We try to synthesize a linear
          // formula of the form `conditon = c1 * action + c2` using z3.
          z3::expr key_read = z3builder.toZ3Expr(PerryReadExpr::alloc(
            key.first.sym.name,
            PerryConstantExpr::alloc(key.first.sym.width, key.first.sym.idx),
            key.first.sym.width));
          z3::expr val_read = z3builder.toZ3Expr(PerryReadExpr::alloc(
            val.sym.name,
            PerryConstantExpr::alloc(val.sym.width, val.sym.idx),
            val.sym.width));
          bool success = false;
          auto new_symbol = z3builder.getSym(val.sym.width);
          auto res = z3builder.synthesizeLinearFormula(
            z3builder.toZ3ExprAnd(key.first.constraints_added),
            z3builder.toZ3ExprAnd(key.first.constraints),
            key_read, z3builder.toZ3Expr(val.after), new_symbol, success);
          if (success) {
            final_val_constraint = (val_read == new_symbol);
            bit_constraints_key = (key_read == res);
          }
        }
      }
      if (!bit_constraints_key.is_true() && final_val_constraint.is_true()) {
        // the condition can be inferred, but the corresponding action cannot
        z3::expr val_read = z3builder.toZ3Expr(PerryReadExpr::alloc(
            val.sym.name,
            PerryConstantExpr::alloc(val.sym.width, val.sym.idx),
            val.sym.width));
        final_val_constraint = (val_read == z3builder.getSym(val.sym.width));
      }
      if (wr_expr_id_to_idx.find(final_val_constraint.id()) ==
          wr_expr_id_to_idx.end())
      {
        wr_expr_id_to_idx.insert(
          std::make_pair(final_val_constraint.id(), wr_conds.size()));
        wr_conds.push_back(final_val_constraint);
        wr_actions.push_back(z3::expr_vector(z3builder.getContext()));
      }
      auto cur_idx = wr_expr_id_to_idx[final_val_constraint.id()];
      wr_actions[cur_idx].push_back(bit_constraints_key);
      if (reset_constraint_key) {
        bit_constraints_key = z3builder.getContext().bool_val(true);
      }
    }
  }
  
  z3::solver s(z3builder.getContext());
  
  // TODO: this is ugly, consider refining this
  std::string SymName = FunctionToSymbolName.at(*(TopLevelFunctions.begin()));

  std::string OP = PerryOutputFile;
  if (OP.empty()) {
    klee_warning("Empty output file path for Perry, default to perry-out.json");
    OP = "./perry-out.json";
  }
  FILE *OF = fopen(OP.c_str(), "w");
  if (!OF) {
    klee_error("Failed to open output file");
  }
  std::string OutContent;
  OutContent += "{\n";

  // read data registers
  OutContent += "\t\"RD\": [";
  for (auto RD : readDataRegIdx) {
    OutContent += std::to_string(RD);
    OutContent += ", ";
  }
  if (!readDataRegIdx.empty()) {
    OutContent = OutContent.substr(0, OutContent.size() - 2);
  }
  OutContent += "],\n";
  // wirtten data registers
  OutContent += "\t\"WD\": [";
  for (auto RD : writtenDataRegIdx) {
    OutContent += std::to_string(RD);
    OutContent += ", ";
  }
  if (!writtenDataRegIdx.empty()) {
    OutContent = OutContent.substr(0, OutContent.size() - 2);
  }
  OutContent += "],\n";

  // add constraints
  std::regex LineBreak("\n");
  OutContent += "\t\"read_constraint\": \"";
  if (unique_constraints_read.size() > 0) {
    std::cerr << "read constraint: \n";
    auto rc = z3builder.getLogicalBitExprBatchOr(unique_constraints_read, SymName);
    std::cerr << rc << "\n";
    s.add(rc);
    std::cerr << s.check() << "\n";
    std::cerr << s.get_model() << "\n";
    std::string smt2dump = s.to_smt2();
    OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
  }
  OutContent += "\",\n";

  OutContent += "\t\"write_constraint\": \"";
  if (unique_constraints_write.size() > 0) {
    std::cerr << "\nwrite constraint: \n";
    auto wc = z3builder.getLogicalBitExprBatchOr(unique_constraints_write, SymName);
    std::cerr << wc << "\n";
    s.reset();
    s.add(wc);
    std::cerr << s.check() << "\n";
    std::cerr << s.get_model() << "\n";
    std::string smt2dump = s.to_smt2();
    OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
  }
  OutContent += "\",\n";

  OutContent += "\t\"irq_constraint\": \"";
  if (unique_constraints_irq.size() > 0) {
    std::cerr << "\nirq constraint: \n";
    auto wc = z3builder.getLogicalBitExprBatchOr(unique_constraints_irq, SymName);
    std::cerr << wc << "\n";
    s.reset();
    s.add(wc);
    std::cerr << s.check() << "\n";
    std::cerr << s.get_model() << "\n";
    std::string smt2dump = s.to_smt2();
    OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
  }
  OutContent += "\",\n";

  OutContent += "\t\"between_writes_constraint\": \"";
  if (unique_constraints_between_writes.size() > 0) {
    std::cerr << "\nconstraint between writes: \n";
    auto wc = z3builder.getLogicalBitExprBatchOr(unique_constraints_between_writes, SymName);
    std::cerr << wc << "\n";
    s.reset();
    s.add(wc);
    std::cerr << s.check() << "\n";
    std::cerr << s.get_model() << "\n";
    std::string smt2dump = s.to_smt2();
    OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
  }
  OutContent += "\",\n";

  z3::expr_vector unique_constraints_final(z3builder.getContext());
  OutContent += "\t\"post_writes_constraint\": \"";
  for (auto &ucf : unique_constraints_final_per_function) {
    if (ucf.empty()) {
      continue;
    }
    auto wc = z3builder.getLogicalBitExprBatchOr(ucf, SymName);
    if (wc.is_true()) {
      continue;
    }
    unique_constraints_final.push_back(wc);
  }
  if (unique_constraints_final.size() > 0) {
    std::cerr << "\nconstraint final diff: \n";
    auto wc = z3builder.getLogicalBitExprOr(unique_constraints_final, false, true);
    std::cerr << wc << "\n";
    s.reset();
    s.add(wc);
    std::cerr << s.check() << "\n";
    std::cerr << s.get_model() << "\n";
    std::string smt2dump = s.to_smt2();
    OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
  }
  OutContent += "\",\n";

  
  // condition-action lists
  OutContent += "\t\"cond_actions\": [\n";
  unsigned num_conds = rr_conds.size();
  bool has_cond_action_content = false;
  for (unsigned i = 0; i < num_conds; ++i) {
    auto &action_set = rr_actions[i];
    if (rr_conds[i].is_true() || rr_conds[i].is_false()) {
      klee_warning("Failed to infer actions for RR condition:\n%s\naction is:\n%s",
                    rr_conds[i].to_string().c_str(),
                    action_set.to_string().c_str());
      continue;
    }
    // this is safe
    auto final_action = z3builder.getLogicalBitExprOr(action_set, false, true);
    if (final_action.is_true()) {
      klee_warning("Failed to infer actions for RR condition:\n%s\naction is:\n%s",
                   rr_conds[i].to_string().c_str(),
                   action_set.to_string().c_str());
      continue;
    }
    has_cond_action_content = true;
    rr_actions_final.push_back(final_action);
    std::cerr << "RR Rule: ##################################\n"
              << "When:\n"
              << rr_conds[i]
              << "\nholds, take the following action:\n"
              << final_action
              << "\n";
    OutContent += "\t\t{\n";
    OutContent += "\t\t\t\"cond\": \"";
    s.reset();
    s.add(rr_conds[i]);
    std::string smt2dump = s.to_smt2();
    OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
    OutContent += "\",\n";
    OutContent += "\t\t\t\"action\": \"";
    s.reset();
    s.add(final_action);
    smt2dump = s.to_smt2();
    OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
    OutContent += "\"\n";
    OutContent += "\t\t},\n";
  }
  
  num_conds = wr_conds.size();
  for (unsigned i = 0; i < num_conds; ++i) {
    auto &action_set = wr_actions[i];
    if (wr_conds[i].is_true() || wr_conds[i].is_false()) {
      klee_warning("Failed to infer actions for WR condition:\n%s\naction is:\n%s",
                    wr_conds[i].to_string().c_str(),
                    action_set.to_string().c_str());
      continue;
    }
    z3::expr_vector new_action_set(z3builder.getContext());
    for (auto action : action_set) {
      if (z3builder.contains_bv_const(action, "tmp:0:", false)) {
        // just output this
        has_cond_action_content = true;
        std::cerr << "WR Rule: ##################################\n"
                  << "When:\n"
                  << wr_conds[i]
                  << "\nholds, take the following action:\n"
                  << action
                  << "\n";
        OutContent += "\t\t{\n";
        OutContent += "\t\t\t\"cond\": \"";
        s.reset();
        s.add(wr_conds[i]);
        std::string smt2dump = s.to_smt2();
        OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
        OutContent += "\",\n";
        OutContent += "\t\t\t\"action\": \"";
        s.reset();
        s.add(action);
        smt2dump = s.to_smt2();
        OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
        OutContent += "\"\n";
        OutContent += "\t\t},\n";
      } else {
        new_action_set.push_back(action);
      }
    }

    if (new_action_set.empty()) {
      continue;
    }
    auto final_action = z3builder.getLogicalBitExprOr(new_action_set, false, true);
    if (final_action.is_true()) {
      klee_warning("Failed to infer actions for WR condition:\n%s\naction is:\n%s",
                   wr_conds[i].to_string().c_str(),
                   new_action_set.to_string().c_str());
      continue;
    }
    has_cond_action_content = true;
    std::cerr << "WR Rule: ##################################\n"
              << "When:\n"
              << wr_conds[i]
              << "\nholds, take the following action:\n"
              << final_action
              << "\n";
    OutContent += "\t\t{\n";
    OutContent += "\t\t\t\"cond\": \"";
    s.reset();
    s.add(wr_conds[i]);
    std::string smt2dump = s.to_smt2();
    OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
    OutContent += "\",\n";
    OutContent += "\t\t\t\"action\": \"";
    s.reset();
    s.add(final_action);
    smt2dump = s.to_smt2();
    OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
    OutContent += "\"\n";
    OutContent += "\t\t},\n";
  }
  if (has_cond_action_content) {
    OutContent = OutContent.substr(0, OutContent.length() - 2);
    OutContent += "\n";
  }
  OutContent += "\t]";

  // write ETH constraints, if any
  if (perry_eth_info->rx_desc_reg_offset != -1) {
    OutContent += ",\n";

    OutContent += "\t\"eth_desc_size\": ";
    OutContent += std::to_string(perry_eth_info->desc_struct_size);
    OutContent += ",\n";

    OutContent += "\t\"eth_rx_desc_reg_offset\": ";
    OutContent += std::to_string(perry_eth_info->rx_desc_reg_offset);
    OutContent += ",\n";

    OutContent += "\t\"eth_tx_desc_reg_offset\": ";
    OutContent += std::to_string(perry_eth_info->tx_desc_reg_offset);
    OutContent += ",\n";

    OutContent += "\t\"eth_desc_tx_buf_len\": [";
    OutContent += std::to_string(perry_eth_info->desc_tx_buf_len.offset);
    OutContent += ", ";
    OutContent += std::to_string(perry_eth_info->desc_tx_buf_len.start_bit);
    OutContent += ", ";
    OutContent += std::to_string(perry_eth_info->desc_tx_buf_len.num_bits);
    OutContent += "],\n";

    OutContent += "\t\"eth_desc_rx_frame_len\": [";
    OutContent += std::to_string(perry_eth_info->desc_rx_frame_len.offset);
    OutContent += ", ";
    OutContent += std::to_string(perry_eth_info->desc_rx_frame_len.start_bit);
    OutContent += ", ";
    OutContent += std::to_string(perry_eth_info->desc_rx_frame_len.num_bits);
    OutContent += "],\n";

    OutContent += "\t\"eth_desc_buf\": [";
    OutContent += std::to_string(perry_eth_info->desc_buf.offset);
    OutContent += ", ";
    OutContent += std::to_string(perry_eth_info->desc_buf.start_bit);
    OutContent += ", ";
    OutContent += std::to_string(perry_eth_info->desc_buf.num_bits);
    OutContent += "],\n";

    OutContent += "\t\"eth_desc_rx_buf_len\": ";
    if (perry_eth_info->desc_rx_buf_len_stored_in_reg) {
      OutContent += std::to_string(perry_eth_info->desc_rx_buf_len.reg_offset);
      OutContent += ",\n";
    } else {
      OutContent += "[";
      OutContent += std::to_string(perry_eth_info->desc_rx_buf_len.f.offset);
      OutContent += ", ";
      OutContent += std::to_string(perry_eth_info->desc_rx_buf_len.f.start_bit);
      OutContent += ", ";
      OutContent += std::to_string(perry_eth_info->desc_rx_buf_len.f.num_bits);
      OutContent += "],\n";
    }

    OutContent += "\t\"eth_desc_mem_layout\": \"";
    switch (perry_eth_info->mem_layout) {
      case PerryEthInfo::UNKNOWN: {
        OutContent += "UNKOWN";
        break;
      }
      case PerryEthInfo::RINGBUF: {
        OutContent += "RINGBUF";
        break;
      }
      case PerryEthInfo::ARRAY: {
        OutContent += "ARRAY";
        break;
      }
    }
    OutContent += "\",\n";

    if (perry_eth_info->mem_layout == PerryEthInfo::RINGBUF) {
      OutContent += "\t\"eth_desc_next_desc\": [";
      OutContent += std::to_string(perry_eth_info->desc_next_desc.offset);
      OutContent += ", ";
      OutContent += std::to_string(perry_eth_info->desc_next_desc.start_bit);
      OutContent += ", ";
      OutContent += std::to_string(perry_eth_info->desc_next_desc.num_bits);
      OutContent += "],\n";
    } else if (perry_eth_info->mem_layout == PerryEthInfo::ARRAY) {
      std::vector<std::vector<ref<PerryExpr>>> eth_last_desc_cs {
      std::vector<ref<PerryExpr>>(
          perry_eth_info->last_desc_cs.begin(),
          perry_eth_info->last_desc_cs.end()
        )
      };
      OutContent += "\t\"eth_last_desc_constraints\": \"";
      if (perry_eth_info->last_desc_cs.size() > 0) {
        std::cerr << "ETH last descriptor constraints: \n";
        auto rc = z3builder.getLogicalBitExprBatchOr(eth_last_desc_cs, "d");
        std::cerr << rc << "\n";
        s.reset();
        s.add(rc);
        std::cerr << s.check() << "\n";
        std::cerr << s.get_model() << "\n";
        std::string smt2dump = s.to_smt2();
        OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
      }
      OutContent += "\",\n";
    }

    std::vector<std::vector<ref<PerryExpr>>> eth_last_seg_cs {
      std::vector<ref<PerryExpr>>(
        perry_eth_info->last_seg_cs.begin(),
        perry_eth_info->last_seg_cs.end()
      )
    };
    OutContent += "\t\"eth_last_seg_constraints\": \"";
    if (perry_eth_info->last_seg_cs.size() > 0) {
      std::cerr << "ETH last seg constraints: \n";
      auto rc = z3builder.getLogicalBitExprBatchOr(eth_last_seg_cs, "d");
      std::cerr << rc << "\n";
      s.reset();
      s.add(rc);
      std::cerr << s.check() << "\n";
      std::cerr << s.get_model() << "\n";
      std::string smt2dump = s.to_smt2();
      OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
    }
    OutContent += "\",\n";

    std::vector<std::vector<ref<PerryExpr>>> eth_avail_seg_cs {
      std::vector<ref<PerryExpr>>(
        perry_eth_info->avail_cs.begin(),
        perry_eth_info->avail_cs.end()
      )
    };
    OutContent += "\t\"eth_avail_seg_constraints\": \"";
    if (perry_eth_info->avail_cs.size() > 0) {
      std::cerr << "ETH available seg constraints: \n";
      auto rc = z3builder.getLogicalBitExprBatchOr(eth_avail_seg_cs, "d");
      std::cerr << rc << "\n";
      s.reset();
      s.add(rc);
      std::cerr << s.check() << "\n";
      std::cerr << s.get_model() << "\n";
      std::string smt2dump = s.to_smt2();
      OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
    }
    OutContent += "\",\n";

    std::vector<std::vector<ref<PerryExpr>>> eth_first_seg_cs {
      std::vector<ref<PerryExpr>>(
        perry_eth_info->first_seg_cs.begin(),
        perry_eth_info->first_seg_cs.end()
      )
    };
    OutContent += "\t\"eth_first_seg_constraints\": \"";
    if (perry_eth_info->first_seg_cs.size() > 0) {
      std::cerr << "ETH first seg constraints: \n";
      auto rc = z3builder.getLogicalBitExprBatchOr(eth_first_seg_cs, "d");
      std::cerr << rc << "\n";
      s.reset();
      s.add(rc);
      std::cerr << s.check() << "\n";
      std::cerr << s.get_model() << "\n";
      std::string smt2dump = s.to_smt2();
      OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
    }
    OutContent += "\"";
  }

  // write timer constraints, if any
  if (perry_timer_info->counter_reg_offset != -1) {
    OutContent += ",\n";

    OutContent += "\t\"timer_period_reg_offset\": ";
    OutContent += std::to_string(perry_timer_info->period_reg_offset);
    OutContent += ",\n";

    OutContent += "\t\"timer_counter_reg_offset\": ";
    OutContent += std::to_string(perry_timer_info->counter_reg_offset);
    OutContent += ",\n";

    OutContent += "\t\"timer_enable_action\": \"";
    if (!timer_enable_conds.empty()) {
      std::cerr << "Timer Enable Action: \n";
      z3::expr tmp = timer_enable_conds.size() == 1 ? timer_enable_conds.back()
                                                    : z3::mk_or(timer_enable_conds);
      std::cerr << tmp << "\n";
      s.reset();
      s.add(tmp);
      std::cerr << s.check() << "\n";
      std::cerr << s.get_model() << "\n";
      std::string smt2dump = s.to_smt2();
      OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
    }
    OutContent += "\",\n";

    OutContent += "\t\"timer_disable_action\": \"";
    if (!timer_disable_conds.empty()) {
      std::cerr << "Timer Disable Action: \n";
      z3::expr tmp = timer_disable_conds.size() == 1 ? timer_disable_conds.back()
                                                    : z3::mk_or(timer_disable_conds);
      std::cerr << tmp << "\n";
      s.reset();
      s.add(tmp);
      std::cerr << s.check() << "\n";
      std::cerr << s.get_model() << "\n";
      std::string smt2dump = s.to_smt2();
      OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
    }
    OutContent += "\",\n";

    OutContent += "\t\"timer_irq_cond\": \"";
    if (!timer_irq_conds.empty()) {
      std::cerr << "Timer Interrupt Condition: \n";
      auto rc = z3builder.getLogicalBitExprBatchOr(timer_irq_conds, SymName);
      std::cerr << rc << "\n";
      s.reset();
      s.add(rc);
      std::cerr << s.check() << "\n";
      std::cerr << s.get_model() << "\n";
      std::string smt2dump = s.to_smt2();
      OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
    }
    OutContent += "\"";
  }

  if (!final_src_dst.empty()) {
    OutContent += ",\n";

    OutContent += "\t\"dma_src_dst_cnt_tuples\": [\n";
    bool add_comma = false;
    for (auto &ent : final_src_dst) {
      if (add_comma) {
        OutContent += ",\n";
      }
      OutContent += "\t\t{ \"src\": ";
      OutContent += std::to_string(std::get<0>(ent.first));
      OutContent += ", \"dst\": ";
      OutContent += std::to_string(std::get<1>(ent.first));
      OutContent += ", \"cnt\": ";
      OutContent += std::to_string(std::get<2>(ent.first));
      OutContent += ", \"cond\": \"";
      s.reset();
      s.add(ent.second);
      std::string smt2dump = s.to_smt2();
      OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
      OutContent += "\" }";
      add_comma = true;
    }
    OutContent += "\n\t]";
  }

  bool has_dma_xfer_cplt_irq_conds = false;
  for (unsigned ii = 0; ii < dma_xfer_cplt_irq_conds.size(); ++ii) {
    if (dma_xfer_cplt_irq_conds[ii].empty()) {
      continue;
    }
    has_dma_xfer_cplt_irq_conds = true;
    break;
  }

  if (has_dma_xfer_cplt_irq_conds) {
    OutContent += ",\n";

    OutContent += "\t\"dma_xfer_cplt_irq_conds\": [\n";
    bool add_comma = false;
    for (unsigned ii = 0; ii < dma_xfer_cplt_irq_conds.size(); ++ii) {
      if (dma_xfer_cplt_irq_conds[ii].empty()) {
        continue;
      }
      if (add_comma) {
        OutContent += ",\n";
      }
      std::cerr << "DMA Xfer Cplt Condition for Channel " << ii << "\n";
      auto rc = z3builder.getLogicalBitExprBatchOr(dma_xfer_cplt_irq_conds[ii], SymName);
      std::cerr << rc << "\n";
      s.reset();
      s.add(rc);
      std::string smt2dump = s.to_smt2();
      OutContent += "\t\t{ \"channel\": ";
      OutContent += std::to_string(ii);
      OutContent += ", \"cond\": \"";
      OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
      OutContent += "\" }";
      add_comma = true;
    }
    OutContent += "\n\t]";
  }

  if (!dma_enable_conds.empty()) {
    OutContent += ",\n";

    OutContent += "\t\"dma_enable_conds\": [\n";
    bool add_comma = false;
    for (const auto &dec : dma_enable_conds) {
      if (add_comma) {
        OutContent += ",\n";
      }
      s.reset();
      s.add(dec);
      std::string smt2dump = s.to_smt2();
      OutContent += "\t\t\"";
      OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
      OutContent += "\"";
      add_comma = true;
    }
    OutContent += "\n\t]";
  }

  if (!dma_disable_conds.empty()) {
    OutContent += ",\n";

    OutContent += "\t\"dma_disable_conds\": [\n";
    bool add_comma = false;
    for (const auto &dec : dma_disable_conds) {
      if (add_comma) {
        OutContent += ",\n";
      }
      s.reset();
      s.add(dec);
      std::string smt2dump = s.to_smt2();
      OutContent += "\t\t\"";
      OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
      OutContent += "\"";
      add_comma = true;
    }
    OutContent += "\n\t]";
  }

  if (!dma_rx_enable_conds.empty()) {
    OutContent += ",\n";

    OutContent += "\t\"dma_rx_enable_conds\": \"";
    s.reset();
    z3::expr tmp = dma_rx_enable_conds.size() == 1 ? dma_rx_enable_conds.back()
                                                   : z3::mk_or(dma_rx_enable_conds);
    s.add(tmp);
    std::string smt2dump = s.to_smt2();
    OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
    OutContent += "\"";
  }

  if (!dma_rx_disable_conds.empty()) {
    OutContent += ",\n";

    OutContent += "\t\"dma_rx_disable_conds\": \"";
    s.reset();
    z3::expr tmp = dma_rx_disable_conds.size() == 1 ? dma_rx_disable_conds.back()
                                                    : z3::mk_or(dma_rx_disable_conds);
    s.add(tmp);
    std::string smt2dump = s.to_smt2();
    OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
    OutContent += "\"";
  }

  if (!dma_tx_enable_conds.empty()) {
    OutContent += ",\n";

    OutContent += "\t\"dma_tx_enable_conds\": \"";
    s.reset();
    z3::expr tmp = dma_tx_enable_conds.size() == 1 ? dma_tx_enable_conds.back()
                                                   : z3::mk_or(dma_tx_enable_conds);
    s.add(tmp);
    std::string smt2dump = s.to_smt2();
    OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
    OutContent += "\"";
  }

  if (!dma_tx_disable_conds.empty()) {
    OutContent += ",\n";

    OutContent += "\t\"dma_tx_disable_conds\": \"";
    s.reset();
    z3::expr tmp = dma_tx_disable_conds.size() == 1 ? dma_tx_disable_conds.back()
                                                    : z3::mk_or(dma_tx_disable_conds);
    s.add(tmp);
    std::string smt2dump = s.to_smt2();
    OutContent += std::regex_replace(smt2dump, LineBreak, "\\n");
    OutContent += "\"";
  }

  OutContent += "\n}";
  fwrite(OutContent.c_str(), 1, OutContent.size(), OF);
  fclose(OF);
}

int main(int argc, char **argv) {
  atexit(llvm_shutdown);  // Call llvm_shutdown() on exit.

#if LLVM_VERSION_CODE >= LLVM_VERSION(13, 0)
  KCommandLine::HideOptions(llvm::cl::getGeneralCategory());
#else
  KCommandLine::HideOptions(llvm::cl::GeneralCategory);
#endif

  llvm::InitializeNativeTarget();

  parseArguments(argc, argv);
  sys::PrintStackTraceOnErrorSignal(argv[0]);

  sys::SetInterruptFunction(interrupt_handle);

  // Load the bytecode...
  std::string errorMsg;
  LLVMContext ctx;
  std::vector<std::unique_ptr<llvm::Module>> loadedModules;
  if (!klee::loadFile(InputFile, ctx, loadedModules, errorMsg)) {
    klee_error("error loading program '%s': %s", InputFile.c_str(),
               errorMsg.c_str());
  }
  // Load and link the whole files content. The assumption is that this is the
  // application under test.
  // Nothing gets removed in the first place.
  std::unique_ptr<llvm::Module> M(klee::linkModules(
      loadedModules, "" /* link all modules together */, errorMsg));
  if (!M) {
    klee_error("error loading program '%s': %s", InputFile.c_str(),
               errorMsg.c_str());
  }

  llvm::Module *mainModule = M.get();

  std::set<std::string> TopLevelFunctions;
  std::map<StructOffset, std::set<std::string>> PtrFunction;
  std::map<std::string, std::unordered_set<uint64_t>> OkValuesMap;
  LoopRangeTy LoopRanges;
  perry_eth_info = new PerryEthInfo();
  perry_timer_info = new PerryTimerInfo();
  perry_dma_info = new PerryDMAInfo();
  loadLoopInfo(LoopRanges);
  collectTopLevelFunctions(*mainModule, TopLevelFunctions, PtrFunction,
                           OkValuesMap);
  EntryPoint = *TopLevelFunctions.begin();

  // most MCUs are 32-bit
  std::string opt_suffix = "32";

  // Add additional user-selected suffix
  opt_suffix += "_" + RuntimeBuild.getValue();

  // TODO: seperate difference cpu
  if (ARMCPUVersion.empty()) {
    klee_error("Must specify CPU version");
  }
  opt_suffix += "_" + ARMCPUVersion.getValue();

  // Push the module as the first entry
  loadedModules.emplace_back(std::move(M));

  std::string LibraryDir = KleeHandler::getRunTimeLibraryPath(argv[0]);
  Interpreter::ModuleOptions Opts(LibraryDir.c_str(), EntryPoint, opt_suffix,
                                  /*Optimize=*/OptimizeModule,
                                  /*CheckDivZero=*/CheckDivZero,
                                  /*CheckOvershift=*/CheckOvershift);
  Opts.TopLevelFunctions = TopLevelFunctions;
  Opts.PtrFunction = PtrFunction;
  Opts.OkValuesMap = OkValuesMap;

  if (WithPOSIXRuntime) {
    SmallString<128> Path(Opts.LibraryDir);
    llvm::sys::path::append(Path, "libkleeRuntimePOSIX" + opt_suffix + ".bca");
    klee_message("NOTE: Using POSIX model: %s", Path.c_str());
    if (!klee::loadFile(Path.c_str(), mainModule->getContext(), loadedModules,
                        errorMsg))
      klee_error("error loading POSIX support '%s': %s", Path.c_str(),
                 errorMsg.c_str());

    std::string libcPrefix = (Libc == LibcType::UcLibc ? "__user_" : "");
    preparePOSIX(loadedModules, libcPrefix);
  }

  if (Libcxx) {
#ifndef SUPPORT_KLEE_LIBCXX
    klee_error("KLEE was not compiled with libc++ support");
#else
    SmallString<128> LibcxxBC(Opts.LibraryDir);
    llvm::sys::path::append(LibcxxBC, KLEE_LIBCXX_BC_NAME);
    if (!klee::loadFile(LibcxxBC.c_str(), mainModule->getContext(), loadedModules,
                        errorMsg))
      klee_error("error loading libc++ '%s': %s", LibcxxBC.c_str(),
                 errorMsg.c_str());
    klee_message("NOTE: Using libc++ : %s", LibcxxBC.c_str());
#ifdef SUPPORT_KLEE_EH_CXX
    SmallString<128> EhCxxPath(Opts.LibraryDir);
    llvm::sys::path::append(EhCxxPath, "libkleeeh-cxx" + opt_suffix + ".bca");
    if (!klee::loadFile(EhCxxPath.c_str(), mainModule->getContext(),
                        loadedModules, errorMsg))
      klee_error("error loading libklee-eh-cxx '%s': %s", EhCxxPath.c_str(),
                 errorMsg.c_str());
    klee_message("NOTE: Enabled runtime support for C++ exceptions");
#else
    klee_message("NOTE: KLEE was not compiled with support for C++ exceptions");
#endif
#endif
  }

  switch (Libc) {
  case LibcType::KleeLibc: {
    // FIXME: Find a reasonable solution for this.
    SmallString<128> Path(Opts.LibraryDir);
    llvm::sys::path::append(Path,
                            "libkleeRuntimeKLEELibc" + opt_suffix + ".bca");
    if (!klee::loadFile(Path.c_str(), mainModule->getContext(), loadedModules,
                        errorMsg))
      klee_error("error loading klee libc '%s': %s", Path.c_str(),
                 errorMsg.c_str());
  }
  /* Falls through. */
  case LibcType::FreestandingLibc: {
    SmallString<128> Path(Opts.LibraryDir);
    llvm::sys::path::append(Path,
                            "libkleeRuntimeFreestanding" + opt_suffix + ".bca");
    if (!klee::loadFile(Path.c_str(), mainModule->getContext(), loadedModules,
                        errorMsg))
      klee_error("error loading freestanding support '%s': %s", Path.c_str(),
                 errorMsg.c_str());
    break;
  }
  case LibcType::UcLibc:
    linkWithUclibc(LibraryDir, opt_suffix, loadedModules);
    break;
  case LibcType::NopNotNever:
    // do nothing
    break;
  }

  for (const auto &library : LinkLibraries) {
    if (!klee::loadFile(library, mainModule->getContext(), loadedModules,
                        errorMsg))
      klee_error("error loading bitcode library '%s': %s", library.c_str(),
                 errorMsg.c_str());
  }

  // All modules are loaded till here

  // Craft a long-standing KModule
  KModule *kmodule = new KModule();
  std::map<std::string, std::string> FunctionToSymbolName;
  kmodule->setupAll(loadedModules, Opts, FunctionToSymbolName);
  ControlDependenceGraphPass::NodeSet ns;
  ControlDependenceGraphPass::NodeMap nm;
  kmodule->prepareCDG(TopLevelFunctions, ns, nm);
  std::unordered_set<llvm::BasicBlock *> loopExitingBlocks;
  kmodule->collectLoopExitingBlocks(loopExitingBlocks);
  externalsAndGlobalsCheck(kmodule->module.get());

  // maybe we only need to replay the path
  std::vector<bool> replayPath;
  Interpreter::InterpreterOptions IOpts;
  setInterpreterOptions(IOpts, Interpreter::TaintOption::DirectTaint,
                        false, 0);
  signal(SIGALRM, timeoutHandler);
  sys::SetInterruptFunction(interrupt_handle_watchdog);
  TaintSet liveTaint;
  std::vector<PerryRecord> records;
  std::map<std::string, std::vector<PerryRecord>> all_records;
  PerryExprManager PEM;

  bool do_bind = true;
  std::unordered_set<std::string> perry_func_hooks;
  for (auto &fh : PerryFunctionHooks) {
    perry_func_hooks.insert(fh);
  }
  auto start_time = std::chrono::system_clock::now();
  for (auto TopFunc : TopLevelFunctions) {
    records.clear();
    singlerun(replayPath, IOpts, ctx, Opts, kmodule, "__perry_dummy_" + TopFunc,
              liveTaint, records, PEM, loopExitingBlocks, LoopRanges, perry_func_hooks, do_bind);
    all_records[TopFunc] = std::move(records);
    do_bind = false;
  }
  auto end_time = std::chrono::system_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
  klee_message("Trace collection consumed: %ld\n", duration.count());
  start_time = std::chrono::system_clock::now();
  postProcess(TopLevelFunctions, FunctionToSymbolName, all_records, liveTaint,
              OkValuesMap, nm, LoopRanges);

  end_time = std::chrono::system_clock::now();
  duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
  klee_message("Model inference consumed: %ld\n", duration.count());
  // release memory
  delete kmodule;
  for (auto node : ns) {
    delete node;
  }
  delete perry_eth_info;
  perry_eth_info = nullptr;

  delete perry_timer_info;
  perry_timer_info = nullptr;

  delete perry_dma_info;
  perry_dma_info = nullptr;

  return 0;
}

static void daemonWaitFeedback(int fd, TaintSet &ts) {
  TaintTy t;
  while (1) {
    if (read(fd, &t, sizeof(t)) != sizeof(t)) {
      break;
    }
    ts.insert(t);
  }
  close(fd);
}

static void runDaemon(int pid, int wfd, int rfd, TaintSet &ts) {
  workerPID = pid;
  klee_message("PERRY: daemon started, watching %d", pid);
  fflush(stderr);

  time::Span seconds;
  bool TimeIsGiven = !MaxTime.empty();
  if (TimeIsGiven) {
    seconds = time::Span(MaxTime);
  }

  itimerval it;
  if (TimeIsGiven) {
    klee_message(
      "PERRY: watchdog started, the target will be halted after %ld seconds",
      seconds.toMicroseconds() / 1000000);
      
      // setup the timer
      it.it_value.tv_usec = seconds.toMicroseconds();
      it.it_value.tv_sec = it.it_value.tv_usec / 1000000;
      setitimer(ITIMER_REAL, &it, NULL);
  }

  // inform child that we're ready
  int status;
  if (write(wfd, &status, sizeof(status)) != sizeof(status)) {
    klee_error("Failed to write pipe");
  }
  daemonWaitFeedback(rfd, ts);
  close(wfd);
  int res = waitpid(pid, &status, 0);

  if (TimeIsGiven) {
    // stop the timer
    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);
  }

  // child exits
  if (res < 0) {
    if (errno == ECHILD) {
      klee_warning("KLEE: daemon exiting (no child)");
    } if (errno != EINTR) {
      perror("watchdog waitpid");
      exit(1);
    }
  } else if (res == pid && WIFEXITED(status)) {
    klee_message(
      "KLEE: child exit caught in daemon\n"
      "######################################################################");
  } else {
    klee_warning("KLEE: error");
  }
}

static void runKlee(std::vector<bool> &replayPath,
                    Interpreter::InterpreterOptions &IOpts,
                    LLVMContext &ctx,
                    Interpreter::ModuleOptions &Opts,
                    KModule *kmodule,
                    std::string mainFunctionName,
                    TaintSet &ts,
                    int fd,
                    std::vector<PerryRecord> &records,
                    PerryExprManager &PEM,
                    const std::unordered_set<llvm::BasicBlock*> &loopExitingBlocks,
                    LoopRangeTy &loopRange,
                    const std::unordered_set<std::string> &FunctionHooks,
                    bool do_bind)
{
  KleeHandler *handler = new KleeHandler(0, nullptr);
  Interpreter *interpreter =
    theInterpreter
      = Interpreter::create(ctx, IOpts, handler, PEM, loopExitingBlocks, loopRange, FunctionHooks);
  assert(interpreter);
  handler->setInterpreter(interpreter);

  handler->getInfoStream() << "PID: " << getpid() << "\n";

  // Get the desired main function.  klee_main initializes uClibc
  // locale and other data and then calls main.

  // auto finalModule = interpreter->setModule(loadedModules, Opts);
  auto finalModule
    = interpreter->setModuleNoFuss(std::unique_ptr<KModule>(kmodule), Opts);
  interpreter->outputModuleManifest();
  Function *mainFn = finalModule->getFunction(mainFunctionName);
  if (!mainFn) {
    klee_error("Entry function '%s' not found in module.",
               mainFunctionName.c_str());
  }

  if (!replayPath.empty()) {
    interpreter->setReplayPath(&replayPath);
  }


  auto startTime = std::time(nullptr);
  { // output clock info and start time
    std::stringstream startInfo;
    startInfo << time::getClockInfo()
              << "Started: "
              << std::put_time(std::localtime(&startTime), "%Y-%m-%d %H:%M:%S") << '\n';
    handler->getInfoStream() << startInfo.str();
    handler->getInfoStream().flush();
  }

  std::vector<KTest *> seeds;
  for (std::vector<std::string>::iterator
          it = SeedOutFile.begin(), ie = SeedOutFile.end();
        it != ie; ++it) {
    KTest *out = kTest_fromFile(it->c_str());
    if (!out) {
      klee_error("unable to open: %s\n", (*it).c_str());
    }
    seeds.push_back(out);
  }
  for (std::vector<std::string>::iterator
          it = SeedOutDir.begin(), ie = SeedOutDir.end();
        it != ie; ++it) {
    std::vector<std::string> kTestFiles;
    KleeHandler::getKTestFilesInDir(*it, kTestFiles);
    for (std::vector<std::string>::iterator
            it2 = kTestFiles.begin(), ie = kTestFiles.end();
          it2 != ie; ++it2) {
      KTest *out = kTest_fromFile(it2->c_str());
      if (!out) {
        klee_error("unable to open: %s\n", (*it2).c_str());
      }
      seeds.push_back(out);
    }
    if (kTestFiles.empty()) {
      klee_error("seeds directory is empty: %s\n", (*it).c_str());
    }
  }

  if (!seeds.empty()) {
    klee_message("KLEE: using %lu seeds\n", seeds.size());
    interpreter->useSeeds(&seeds);
  }
  if (RunInDir != "") {
    int res = chdir(RunInDir.c_str());
    if (res < 0) {
      klee_error("Unable to change directory to: %s - %s", RunInDir.c_str(),
                  sys::StrError(errno).c_str());
    }
  }
  interpreter->runFunctionJustAsIt(mainFn, do_bind);

  while (!seeds.empty()) {
    kTest_free(seeds.back());
    seeds.pop_back();
  }

  auto endTime = std::time(nullptr);
  { // output end and elapsed time
    std::uint32_t h;
    std::uint8_t m, s;
    std::tie(h,m,s) = time::seconds(endTime - startTime).toHMS();
    std::stringstream endInfo;
    endInfo << "Finished: "
            << std::put_time(std::localtime(&endTime), "%Y-%m-%d %H:%M:%S") << '\n'
            << "Elapsed: "
            << std::setfill('0') << std::setw(2) << h
            << ':'
            << std::setfill('0') << std::setw(2) << +m
            << ':'
            << std::setfill('0') << std::setw(2) << +s
            << '\n';
            handler->getInfoStream() << endInfo.str();
    handler->getInfoStream().flush();
  }

  /// IMPORTANT: keep the universal KModule between runs
  if (!Watchdog) {
    // the same process, just get to it!
    mergeTaint(ts, *interpreter->collectLiveTaints());
    interpreter->collectPerryRecords(records);
  } else {
    klee_error("Not supported yet");
    // pipe
    for (auto t : *interpreter->collectLiveTaints()) {
      (void) write(fd, &t, sizeof(t));
    }
    close(fd);
  }
  interpreter->leakUniversalKModule();
  delete interpreter;

  std::stringstream stats;
  stats << "KLEE: done: [*]" << mainFunctionName
        << "\n"
        << "KLEE: done: completed paths = " << handler->getNumPathsCompleted()
        << '\n'
        << "KLEE: done: partially completed paths = "
        << handler->getNumPathsExplored() - handler->getNumPathsCompleted()
        << '\n'
        << "KLEE: done: generated tests = " << handler->getNumTestCases()
        << "\n###############################################\n";

  bool useColors = llvm::errs().is_displayed();
  if (useColors)
    llvm::errs().changeColor(llvm::raw_ostream::GREEN,
                             /*bold=*/true,
                             /*bg=*/false);

  llvm::errs() << stats.str();

  if (useColors)
    llvm::errs().resetColor();

  handler->getInfoStream() << stats.str();

  delete handler;
}

static void singlerun(std::vector<bool> &replayPath,
                      Interpreter::InterpreterOptions &IOpts,
                      LLVMContext &ctx,
                      Interpreter::ModuleOptions &Opts,
                      KModule *kmodule,
                      std::string mainFunctionName,
                      TaintSet &ts,
                      std::vector<PerryRecord> &records,
                      PerryExprManager &PEM,
                      const std::unordered_set<llvm::BasicBlock*> &loopExitingBlocks,
                      LoopRangeTy &loopRange,
                      const std::unordered_set<std::string> &FunctionHooks,
                      bool do_bind)
{

  // FIXME: Change me to std types.
  // No envs, no args, we treat everything symbolic

  if (Watchdog) {
    klee_error("Not supported yet");
    if (MaxTime.empty()) {
      klee_error("--watchdog used without --max-time");
    }

    int crpwfd[2];
    int cwprfd[2];
    if (pipe(crpwfd)) {
      klee_error("Falied to create pipe");
    }
    if (pipe(cwprfd)) {
      klee_error("Falied to create pipe");
    }

    int pid = fork();
    if (pid < 0) {
      klee_error("unable to fork");
    } else if (pid) {
      // parent run as deamon
      close(crpwfd[0]);
      close(cwprfd[1]);
      runDaemon(pid, crpwfd[1], cwprfd[0], ts);
    } else {
      prctl(PR_SET_PDEATHSIG, SIGKILL);
      close(crpwfd[1]);
      close(cwprfd[0]);
      int trigger;
      if (read(crpwfd[0], &trigger, sizeof(trigger)) != sizeof(trigger)) {
        klee_error("Failed to read from pipe");
      }
      close(crpwfd[0]);
      runKlee(replayPath, IOpts, ctx, Opts, kmodule, mainFunctionName, ts,
              cwprfd[1], records, PEM, loopExitingBlocks, loopRange, FunctionHooks, do_bind);
      exit(0);
    }
  } else {
    // no need to fork
    runKlee(replayPath, IOpts, ctx, Opts, kmodule, mainFunctionName, ts, 0,
            records, PEM, loopExitingBlocks, loopRange, FunctionHooks, do_bind);
  }
}
