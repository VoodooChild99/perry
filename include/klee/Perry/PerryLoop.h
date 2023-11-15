#pragma once

#include "llvm/IR/Instruction.h"
#include "llvm/Support/YAMLParser.h"
#include "llvm/Support/YAMLTraits.h"

#include <map>
#include <unordered_map>
#include <vector>

struct PerryLoopItem {
  std::string FilePath;
  unsigned beginLine = 0;
  unsigned beginColumn = 0;
  unsigned endLine = 0;
  unsigned endColumn = 0;

  PerryLoopItem(const std::string &FilePath, unsigned beginLine,
                unsigned beginColumn, unsigned endLine, unsigned endColumn)
    : FilePath(FilePath), beginLine(beginLine), beginColumn(beginColumn),
      endLine(endLine), endColumn(endColumn) {}
  PerryLoopItem() = default;
  PerryLoopItem(const PerryLoopItem &PI)
    : FilePath(PI.FilePath),
      beginLine(PI.beginLine), beginColumn(PI.beginColumn),
      endLine(PI.endLine), endColumn(PI.endColumn) {}
};

struct PerryLoopItemLoc {
  unsigned beginLine = 0;
  unsigned beginColumn = 0;
  unsigned endLine = 0;
  unsigned endColumn = 0;

  PerryLoopItemLoc(unsigned beginLine, unsigned beginColumn,
                   unsigned endLine, unsigned endColumn)
    : beginLine(beginLine), beginColumn(beginColumn),
      endLine(endLine), endColumn(endColumn) {}
  
  PerryLoopItemLoc(const PerryLoopItemLoc &IL)
    : beginLine(IL.beginLine), beginColumn(IL.beginColumn),
      endLine(IL.endLine), endColumn(IL.endColumn) {}
  
  PerryLoopItemLoc(const PerryLoopItem &PI)
    : beginLine(PI.beginLine), beginColumn(PI.beginColumn),
      endLine(PI.endLine), endColumn(PI.endColumn) {}
  
  // returns true if `this` contains `IL`
  bool contains(unsigned line, unsigned col) const {
    if (line >= beginLine && line <= endLine) {
      if (beginLine == endLine) {
        return (col >= beginColumn && col <= endColumn);
      } else {
        if (line == beginLine) {
          return col >= beginColumn;
        } else if (line == endLine) {
          return col <= endColumn;
        }
        return true;
      }
    } else {
      return false;
    }
  }
};

template<>
struct llvm::yaml::MappingTraits<PerryLoopItem> {
  static void mapping(IO &io, PerryLoopItem &item) {
    io.mapRequired("file", item.FilePath);
    io.mapRequired("begin_line", item.beginLine);
    io.mapRequired("begin_column", item.beginColumn);
    io.mapRequired("end_line", item.endLine);
    io.mapRequired("end_column", item.endColumn);
  }
};

template<>
struct llvm::yaml::SequenceTraits<std::vector<PerryLoopItem>> {
  static size_t size(IO &io, std::vector<PerryLoopItem> &vec) {
    return vec.size();
  }

  static PerryLoopItem &element(IO &io, std::vector<PerryLoopItem> &vec,
                               size_t index) {
    if (index >= vec.size()) {
      vec.resize(index + 1);
    }
    return vec[index];
  }
};

using LoopRangeTy = std::unordered_map<std::string, std::vector<PerryLoopItemLoc>>;

void loadLoopInfo(LoopRangeTy &info);

int inLoopCondition(llvm::Instruction *inst, LoopRangeTy &LoopRanges);