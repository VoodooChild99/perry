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
}

namespace klee {
extern cl::opt<std::string> MaxTime;
class ExecutionState;
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

static void 
collectTopLevelFunctions(llvm::Module& MainModule,
                         std::set<std::string> &TopLevelFunctions,
                         std::map<StructOffset, std::set<std::string>> &PtrFunc,
                         std::map<std::string, std::set<uint64_t>> &OkValuesMap)
{
  llvm::legacy::PassManager pm;
  // collect basic informations
  pm.add(new PerryAnalysisPass(TopLevelFunctions, PtrFunc, OkValuesMap));

  pm.run(MainModule);
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
                      PerryExprManager &PEM);

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

static void
collectContainedSym(const ref<PerryExpr> &PE, std::set<SymRead> &S) {
  std::deque<ref<PerryExpr>> WL;
  WL.push_back(PE);
  while (!WL.empty()) {
    auto E = WL.front();
    WL.pop_front();
    if (auto RE = dyn_cast<PerryReadExpr>(E)) {
      if (auto CE = dyn_cast<PerryConstantExpr>(RE->idx)) {
        S.insert(SymRead(RE->Name, CE->getAPValue().getZExtValue(), RE->width));
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

static bool
containsReadOnlyTO(const ref<PerryExpr> &target, const SymRead &SR) {
  std::deque<ref<PerryExpr>> WL;
  WL.push_back(target);
  while (!WL.empty()) {
    auto E = WL.front();
    WL.pop_front();
    if (E->getKind() == Expr::Read) {
      auto RE = cast<PerryReadExpr>(E);
      if (RE->Name != SR.name) {
        return false;
      }
      if (RE->idx->getKind() != Expr::Constant) {
        return false;
      }
      auto REidx = cast<PerryConstantExpr>(RE->idx);
      SymRead tmpSR(SR.name, REidx->getAPValue().getZExtValue(), RE->getWidth());
      if (!tmpSR.relatedWith(SR)) {
        return false;
      }
    }
    unsigned numKids = E->getNumKids();
    for (unsigned i = 0; i < numKids; ++i) {
      WL.push_back(E->getKid(i));
    }
  }
  return true;
}

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
static int inLoopCondition(Instruction *inst) {
  using SrcLookUpMapValTy 
    = std::set<std::pair<std::pair<unsigned, unsigned>, std::pair<unsigned, unsigned>>>;
  using SrcLookUpMapTy = std::map<std::string, SrcLookUpMapValTy>;
  static SrcLookUpMapTy LookUpMap;
  if (!inst->hasMetadata(LLVMContext::MD_dbg)) {
    return -1;
  }
  auto MDN = inst->getMetadata(LLVMContext::MD_dbg);
  if (MDN->getMetadataID() != Metadata::DILocationKind) {
    klee_error("inLoopCondition: unsupported metadata kind");
  }
  auto DILoc = cast<DILocation>(MDN);
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
  if (LookUpMap.find(file_path) != LookUpMap.end()) {
    for (auto &p : LookUpMap[file_path]) {
      if (read_line >= p.first.first && read_line <= p.second.first &&
          read_col >= p.first.second && read_col <= p.second.second)
      {
        return 1;
      }
    }
  } else {
    // init the entry
    LookUpMap.insert(std::make_pair(file_path, SrcLookUpMapValTy()));
  }

  block_line = read_line;
  block_col = 0;    // read the whole line

  // cannot locate 
  // if (DScope->getMetadataID() != Metadata::DILexicalBlockKind) {
  //   block_line = read_line;
  //   block_col = 0;    // read the whole line
  // } else {
  //   auto DILB = cast<DILexicalBlock>(DScope);
  //   block_line = DILB->getLine();
  //   block_col = DILB->getColumn() - 1;
  // }
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
    LookUpMap[file_path].insert(
      std::make_pair(std::make_pair(block_line, block_col),
                     std::make_pair(block_line_end, block_col_end)));
    if (read_line >= block_line && read_line <= block_line_end &&
        read_col >= block_col && read_col <= block_col_end)
    {
      return 1;
    } else {
      return 0;
    }
  } else {
    klee_error("cannot open src file %s", file_path.c_str());
  }
}

static void
postProcess(const std::set<std::string> &TopLevelFunctions,
            const std::map<std::string, std::string> &FunctionToSymbolName,
            const std::map<std::string, std::vector<PerryRecord>> &allRecords,
            const TaintSet &liveTaint,
            const std::map<std::string, std::set<uint64_t>> &OkValuesMap,
            ControlDependenceGraphPass::NodeMap &nm)
{
  TaintSet byReg;
  for (auto t : liveTaint) {
    addTaint(byReg, t & 0xff000000);
  }
  std::cerr << "Possible data registers: ";
  for (auto t : byReg) {
    std::cerr << t << ", ";
  }
  std::cerr << "\n";

  std::vector<std::vector<ref<PerryExpr>>> unique_constraints_read,
                                           unique_constraints_write,
                                           unique_constraints_irq,
                                           unique_constraints_between_writes,
                                           unique_constraints_final,
                                           unique_rr_constraint;
  std::set<unsigned> writtenDataRegIdx, readDataRegIdx;
  PerryRRDependentMap rrDepMap;
  PerryWRDependentMap wrDepMap;

  bool isIRQ = false;
  PerryZ3Builder z3builder;
  for (auto TopFunc : TopLevelFunctions) {
    assert(FunctionToSymbolName.find(TopFunc) != FunctionToSymbolName.end());
    isIRQ = (TopFunc.find("IRQHandler") != std::string::npos);
    auto SymName = FunctionToSymbolName.at(TopFunc);
    auto &Record = allRecords.at(TopFunc);
    const std::set<uint64_t> *OkVals = nullptr;
    if (OkValuesMap.find(TopFunc) != OkValuesMap.end()) {
      OkVals = &OkValuesMap.at(TopFunc);
    }

    // all state
    unsigned state_idx = 0;
    // for (auto &TR : Trace) {
    for (auto &rec : Record) {
      // single state
      auto &trace = rec.trace;
      auto &final_constraints = rec.final_constraints;
      auto returned_value = rec.return_value;
      auto &reg_accesses = rec.register_accesses;
      auto success_return = rec.success;
      state_idx += 1;
      std::vector<ref<PerryExpr>> lastWriteConstraint;
      bool hasWrite = false;
      bool hasRead = false;
      bool hasNonDataRead = false;
      for (auto &PTI : trace) {
        auto &cur_access = reg_accesses[PTI.reg_access_idx];
        if (cur_access->AccessType == RegisterAccess::REG_READ) {
          // not a data register
          if (byReg.find(cur_access->idx & 0xff000000) == byReg.end()) {
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
          if (byReg.find(cur_access->idx & 0xff000000) == byReg.end()) {
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
          hasRead = true;
          // readDataRegIdx.insert((AC.first.idx & 0xff000000) >> 24);
          readDataRegIdx.insert(cur_access->offset);
          if (!isUniqueConstraints(unique_constraints_read, RegConstraint)) {
            continue;
          } else {
            if (isIRQ) {
              unique_constraints_irq.push_back(RegConstraint);
            }
          }
        } else {
          // writtenDataRegIdx.insert((AC.first.idx & 0xff000000) >> 24);
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
            if (!diffExpr.empty()) {
              (void)
              isUniqueConstraints(unique_constraints_between_writes, diffExpr);
            }
          }
          lastWriteConstraint = RegConstraint;
          if (!isUniqueConstraints(unique_constraints_write, RegConstraint)) {
            continue;
          } else {
            if (isIRQ) {
              unique_constraints_irq.push_back(RegConstraint);
            }
          }
        }
      }

      if (success_return  &&
          OkVals          &&
          OkVals->find(returned_value) != OkVals->end())
      {
        // normal exit
        // data register writes
        if (hasWrite) {
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
          if (!diffFinalCS.empty()) {
            unique_constraints_final.push_back(diffFinalCS);
          }
        }

        // dependent non-data register reads
        if (!hasRead && !hasWrite && hasNonDataRead) {
          // infer reg linkage
          // case 1: two adjacent in-constraint reads
          // case 2: a in-constraint read and previous writes
          unsigned last_idx = 0;
          bool last_is_read = false;

          unsigned trace_size = trace.size();
          for (unsigned i = 0; i < trace_size; ++i) {
            auto &PTI = trace[i];
            unsigned num_cs = PTI.cur_constraints.size();
            auto &cur_access = reg_accesses[PTI.reg_access_idx];

            if (cur_access->AccessType == RegisterAccess::REG_READ) {
              if (last_is_read && last_idx != num_cs) {
                // two adjacent reads, and new constraints are introduced.
                // check whether the newly-introduced constraints contains
                // the result of the previous read.
                auto &last_PTI = trace[i - 1];
                auto &last_access = reg_accesses[last_PTI.reg_access_idx];
                int depend_on_prev 
                  = ControlDependenceGraphPass::isControlDependentOn(
                    nm, cur_access->place->getParent(),
                        last_access->place->getParent());
                
                if (inLoopCondition(cur_access->place) > 0 &&
                    depend_on_prev == 1 && 
                    inNestedScope(last_access->place, cur_access->place)) 
                {
                  auto last_result = last_access->ExprInReg;
                  std::vector<ref<PerryExpr>> before_constraints,
                                              after_constraints;
                  std::set<SymRead> before_syms;
                  collectContainedSym(last_result, before_syms);
                  // look-before to find related constraints
                  for (unsigned j = last_idx; j < num_cs; ++j) {
                    if (containsReadRelated(before_syms, "", PTI.cur_constraints[j])) {
                      before_constraints.push_back(PTI.cur_constraints[j]);
                    }
                  }
                  if (!before_constraints.empty()) {
                    // now we have a potential dependent pair
                    // look-after to find the constraint this read must meet to 
                    // successfully return
                    unsigned num_constraint_on_read;
                    const PerryTrace::Constraints &cs_to_use = (i == trace_size - 1) ? final_constraints : trace[i + 1].cur_constraints;
                    num_constraint_on_read = cs_to_use.size();
                    auto this_result = cur_access->ExprInReg;
                    std::set<SymRead> after_syms;
                    collectContainedSym(this_result, after_syms);
                    for (unsigned j = num_cs; j < num_constraint_on_read; ++j) {
                      if (containsReadRelated(after_syms, "", cs_to_use[j])) {
                        after_constraints.push_back(cs_to_use[j]);
                        // this is somewhat tricky.
                        // we only want the first related constraint, I think this
                        // is resonable.
                        break;
                      }
                    }
                    if (!after_constraints.empty()) {
                      DependentItem key(
                        SymRead(cur_access->name,
                                cur_access->offset,
                                cur_access->width),
                        this_result, after_constraints);
                      if (rrDepMap.find(key) == rrDepMap.end()) {
                        rrDepMap.insert(
                          std::make_pair(key, std::set<DependentItem>()));
                      }
                      DependentItem val(
                        SymRead(last_access->name,
                                last_access->offset,
                                last_access->width),
                        last_result, before_constraints);
                      rrDepMap[key].insert(val);
                    }
                  }
                }
              } else if (!last_is_read && i > 0) {
                if (inLoopCondition(cur_access->place) > 0) {
                  auto &last_PTI = trace[i - 1];
                  auto &last_access = reg_accesses[last_PTI.reg_access_idx];
                  unsigned num_constraint_on_read;
                  const PerryTrace::Constraints &cs_to_use = (i == trace_size - 1) ? final_constraints : trace[i + 1].cur_constraints;
                  num_constraint_on_read = cs_to_use.size();
                  auto this_result = cur_access->ExprInReg;
                  std::set<SymRead> after_syms;
                  collectContainedSym(this_result, after_syms);
                  std::vector<ref<PerryExpr>> after_constraints;
                  for (unsigned j = num_cs; j < num_constraint_on_read; ++j) {
                    if (containsReadRelated(after_syms, "", cs_to_use[j])) {
                      after_constraints.push_back(cs_to_use[j]);
                      break;
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
                    DependentItem key(
                      SymRead(cur_access->name,
                              cur_access->offset,
                              cur_access->width),
                      this_result, after_constraints);
                    if (wrDepMap.find(key) == wrDepMap.end()) {
                      wrDepMap.insert(
                        std::make_pair(key, std::set<DependentWItem>()));
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
                    DependentWItem val(
                      written_reg, before_expr, last_result, before_constraints);
                    if (before_expr) {
                      val.before_sr = cur_reg;
                    }
                    wrDepMap[key].insert(val);
                  }
                }
              }
              last_is_read = true;
              last_idx = num_cs;
            } else {
              last_is_read = false;
              last_idx = num_cs;
            }
          }
        }
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
    z3::expr_vector val_constraints(z3builder.getContext());
    for (auto &val : key.second) {
      std::set<SymRead> fuckSyms;
      collectContainedSym(val.expr, fuckSyms);
      auto wis = z3builder.getLogicalBitExprAnd(val.constraints, "", false, fuckSyms);
      z3::expr_vector bit_level_expr(z3builder.getContext());
      z3builder.getBitLevelExpr(val.expr, bit_level_expr);
      auto bit_constraints
        = z3builder.inferBitLevelConstraint(wis, val.read, bit_level_expr);
      val_constraints.push_back(bit_constraints);
    }
    z3::expr final_val_constraint = z3::mk_and(val_constraints).simplify();
    std::set<SymRead> keySyms;
    collectContainedSym(key.first.expr, keySyms);
    auto key_cs = z3builder.getLogicalBitExprAnd(key.first.constraints, "",
                                                 false, keySyms);
    z3::expr_vector bit_level_expr_key(z3builder.getContext());
    z3builder.getBitLevelExpr(key.first.expr, bit_level_expr_key);
    auto bit_constraints_key
      = z3builder.inferBitLevelConstraint(key_cs, key.first.read,
                                          bit_level_expr_key);
    bit_constraints_key = bit_constraints_key.simplify();
    if (rr_expr_id_to_idx.find(final_val_constraint.id()) == rr_expr_id_to_idx.end()) {
      rr_expr_id_to_idx.insert(std::make_pair(final_val_constraint.id(), rr_conds.size()));
      rr_conds.push_back(final_val_constraint);
      rr_actions.push_back(z3::expr_vector(z3builder.getContext()));
    }
    auto cur_idx = rr_expr_id_to_idx[final_val_constraint.id()];
    rr_actions[cur_idx].push_back(bit_constraints_key);
  }

  // deal with write-read dependences
  // the logic is: if some constraints on the written value is satisfied, some
  // other constraints must be met on the register to be read
  std::map<unsigned, unsigned> wr_expr_id_to_idx;
  z3::expr_vector wr_conds(z3builder.getContext());
  z3::expr_vector wr_actions_final(z3builder.getContext());
  std::vector<z3::expr_vector> wr_actions;
  for (auto &key : wrDepMap) {
    // errs() << "wr##############################\n";
    // errs() << key.first << "----------------------------\n";
    z3::expr_vector val_constraints(z3builder.getContext());
    for (auto &val : key.second) {
      if (!val.constraints.empty()) {
        // there're constraints on the written value
        std::set<SymRead> fuckSyms;
        collectContainedSym(val.after, fuckSyms);
        // errs() << val << "...................................\n";
        auto wis = z3builder.getLogicalBitExprAnd(val.constraints, "",
                                                  false, fuckSyms);
        z3::expr_vector bit_level_expr_before(z3builder.getContext());
        z3::expr_vector bit_level_expr_after(z3builder.getContext());
        if (val.before) {
          z3builder.getBitLevelExpr(val.before, bit_level_expr_before);
        }
        z3builder.getBitLevelExpr(val.after, bit_level_expr_after);
        auto blacklist
          = z3builder.inferBitLevelConstraintRaw(wis, val.before_sr,
                                                 bit_level_expr_before);
        
        auto bit_constraints_after
          = z3builder.inferBitLevelConstraintWithBlacklist(wis,
                                                           val.write,
                                                           blacklist,
                                                           bit_level_expr_after);
        val_constraints.push_back(bit_constraints_after);
      } else {
        // no constraint on the written value
        if (!val.after->getKind() == Expr::Constant) {
          // if the expr written into the register is not a constant, check:
          if (containsReadOnlyTO(val.after, val.write)) {
            // if only the register itself is contained in the expr:
            // errs() << val << "...................................\n";
            z3::expr_vector bit_level_expr_after(z3builder.getContext());
            z3::expr_vector bit_level_expr_before(z3builder.getContext());
            if (val.before) {
              z3builder.getBitLevelExpr(val.before, bit_level_expr_before);
            }
            z3builder.getBitLevelExpr(val.after, bit_level_expr_after);
            auto true_cs = z3builder.getContext().bool_val(true);
            auto blacklist
              = z3builder.inferBitLevelConstraintRaw(true_cs,
                                                     val.before_sr,
                                                     bit_level_expr_before);
            
            auto bit_constraints_after
              = z3builder.inferBitLevelConstraintWithBlacklist(true_cs,
                                                               val.write,
                                                               blacklist,
                                                               bit_level_expr_after);
            val_constraints.push_back(bit_constraints_after);
          } else {
            // else, ignore
            std::string tmp;
            raw_string_ostream OS(tmp);
            val.after->print(OS);
            klee_warning_once(
              0,
              "[WR Dep] No constraint on the written symbolic expression: %s\n%s",
              tmp.c_str(), val.write.to_string().c_str());
            continue;
          }
        } else {
          // the written value is constrained to be this constant
          auto PCE = cast<PerryConstantExpr>(val.after);
          val_constraints.push_back(
            z3builder.getConstantConstraint(val.write,
                                            PCE->getAPValue().getZExtValue()));
        }
      }
    }
    z3::expr final_val_constraint = z3::mk_and(val_constraints).simplify();
    std::set<SymRead> keySyms;
    collectContainedSym(key.first.expr, keySyms);
    auto key_cs = z3builder.getLogicalBitExprAnd(key.first.constraints, "",
                                                 false, keySyms);
    z3::expr_vector bit_level_expr_key(z3builder.getContext());
    z3builder.getBitLevelExpr(key.first.expr, bit_level_expr_key);
    auto bit_constraints_key
      = z3builder.inferBitLevelConstraint(key_cs, key.first.read, bit_level_expr_key);
    bit_constraints_key = bit_constraints_key.simplify();
    if (bit_constraints_key.is_true()) {
      // post constraints are not enough to resolve the constraint on this register
      // this can happen when symbols are compared with symbols.
      // We additionally add constraints on the previously written value and repeat
      // this process. Hopefully this can help.
      z3::expr_vector tmp_vec(z3builder.getContext());
      for (auto &val : key.second) {
        if (val.constraints.empty()) {
          continue;
        }
        std::set<SymRead> fuckSyms;
        collectContainedSym(val.after, fuckSyms);
        auto wis = z3builder.getLogicalBitExprAnd(val.constraints, "",
                                                  false, fuckSyms);
        tmp_vec.push_back(wis);
      }
      tmp_vec.push_back(key_cs);
      key_cs = z3::mk_and(tmp_vec);
      key_cs = key_cs.simplify();
      z3::expr_vector bit_level_expr_again(z3builder.getContext());
      z3builder.getBitLevelExpr(key.first.expr, bit_level_expr_again);
      bit_constraints_key
        = z3builder.inferBitLevelConstraint(key_cs, key.first.read,
                                            bit_level_expr_again);
      bit_constraints_key = bit_constraints_key.simplify();
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

  OutContent += "\t\"post_writes_constraint\": \"";
  if (unique_constraints_final.size() > 0) {
    std::cerr << "\nconstraint final diff: \n";
    auto wc = z3builder.getLogicalBitExprBatchOr(unique_constraints_final, SymName);
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
    // this is safe
    auto final_action = z3builder.getLogicalBitExprOr(action_set, false, true);
    if (final_action.is_true()) {
      klee_warning("Failed to infer actions for condition: %s",
                   rr_conds[i].to_string().c_str());
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
    auto final_action = z3builder.getLogicalBitExprOr(action_set, false, true);
    if (final_action.is_true()) {
      klee_warning("Failed to infer actions for condition: %s",
                   wr_conds[i].to_string().c_str());
      continue;
    }
    has_cond_action_content = true;
    wr_actions_final.push_back(final_action);
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
  OutContent += "\t]\n";

  OutContent += "}";
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
  std::map<std::string, std::set<uint64_t>> OkValuesMap;
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

  for (auto TopFunc : TopLevelFunctions) {
    records.clear();
    singlerun(replayPath, IOpts, ctx, Opts, kmodule, "__perry_dummy_" + TopFunc,
              liveTaint, records, PEM);
    all_records[TopFunc] = std::move(records);
  }

  postProcess(TopLevelFunctions, FunctionToSymbolName, all_records, liveTaint,
              OkValuesMap, nm);

  // release memory
  delete kmodule;
  for (auto node : ns) {
    delete node;
  }

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
                    PerryExprManager &PEM)
{
  KleeHandler *handler = new KleeHandler(0, nullptr);
  Interpreter *interpreter =
    theInterpreter = Interpreter::create(ctx, IOpts, handler, PEM);
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
  interpreter->runFunctionJustAsIt(mainFn);

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
                      PerryExprManager &PEM)
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
              cwprfd[1], records, PEM);
      exit(0);
    }
  } else {
    // no need to fork
    runKlee(replayPath, IOpts, ctx, Opts, kmodule, mainFunctionName, ts, 0,
            records, PEM);
  }
}
