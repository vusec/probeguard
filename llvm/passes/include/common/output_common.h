#ifndef _OUTPUT_COMMON_H
#define _OUTPUT_COMMON_H

using namespace llvm;

#define OUTPUT_DEFAULT_BLOCK_SEP               "\n"
#define OUTPUT_DEFAULT_BLOCK_HEADER_PRE        "["
#define OUTPUT_DEFAULT_BLOCK_HEADER_POST       "]\n"
#define OUTPUT_DEFAULT_ENTRY_SEP               "\n"
#define OUTPUT_DEFAULT_ENTRY_KEY_VALUE_SEP     " = "
#define OUTPUT_DEFAULT_ENTRY_LIST_SEP          ","

namespace llvm {

class OutputUtil;

class OutputEntry {
  public:
      OutputEntry(std::vector<std::string> &key, std::vector<std::string> &value);
      OutputEntry(std::string &key, std::string &value);
      OutputEntry(std::string &key, std::vector<std::string> &value);
      OutputEntry(std::vector<std::string> &key, std::string &value);
      void print(OutputUtil &u, raw_ostream &O);
  private:
      void init(std::vector<std::string> &key, std::vector<std::string> &value);
      void printList(OutputUtil &u, raw_ostream &O, std::vector<std::string> &list);

      std::vector<std::string> key;
      std::vector<std::string> value;
};

class OutputBlock {
  public:
      OutputBlock(std::string &name);
      OutputBlock(const char* name);
      void addEntry(OutputEntry &entry);
      void print(OutputUtil &u, raw_ostream &O);
      size_t size();
  private:
      std::vector<OutputEntry> entries;
      std::string name;
};

class OutputUtil {
  public:
      OutputUtil();
      void addBlock(OutputBlock &block);
      void print(raw_ostream &O);
      static std::string intToStr(long v);
      static std::string uintToStr(unsigned long v);

      std::string blockSep;
      std::string blockHeaderPre;
      std::string blockHeaderPost;
      std::string entrySep;
      std::string entryKeyValueSep;
      std::string entryListSep;
  private:
      std::vector<OutputBlock> blocks;
};

inline OutputEntry::OutputEntry(std::vector<std::string> &key, std::vector<std::string> &value)
{
    init(key, value);
}

inline OutputEntry::OutputEntry(std::string &key, std::string &value)
{
    std::vector<std::string> keys;
    std::vector<std::string> values;
    keys.push_back(key);
    values.push_back(value);
    init(keys, values);
}

inline OutputEntry::OutputEntry(std::string &key, std::vector<std::string> &value)
{
    std::vector<std::string> keys;
    keys.push_back(key);
    init(keys, value);
}

inline OutputEntry::OutputEntry(std::vector<std::string> &key, std::string &value)
{
    std::vector<std::string> values;
    values.push_back(value);
    init(key, values);
}

inline void OutputEntry::print(OutputUtil &u, raw_ostream &O)
{
    assert(key.size() > 0);
    printList(u, O, key);
    O << u.entryKeyValueSep;
    printList(u, O, value);
}

inline void OutputEntry::printList(OutputUtil &u, raw_ostream &O, std::vector<std::string> &list)
{
    for (unsigned i=0;i<list.size();i++) {
        if (i>0) {
            O << u.entryListSep;
        }
        O << list[i];
    }
}

inline void OutputEntry::init(std::vector<std::string> &key, std::vector<std::string> &value)
{
    this->key = key;
    this->value = value;
}

inline OutputBlock::OutputBlock(std::string &name)
{
    this->name = name;
}

inline OutputBlock::OutputBlock(const char *name)
{
    this->name = name;
}


inline void OutputBlock::addEntry(OutputEntry &entry)
{
    entries.push_back(entry);
}

inline void OutputBlock::print(OutputUtil &u, raw_ostream &O)
{
    O << u.blockHeaderPre;
    O << name;
    O << u.blockHeaderPost;
    for (unsigned i=0;i<entries.size();i++) {
        entries[i].print(u, O);
        O << u.entrySep;
    }
}

inline size_t OutputBlock::size()
{
    return entries.size();
}

inline OutputUtil::OutputUtil()
{
    blockSep = OUTPUT_DEFAULT_BLOCK_SEP;
    blockHeaderPre = OUTPUT_DEFAULT_BLOCK_HEADER_PRE;
    blockHeaderPost = OUTPUT_DEFAULT_BLOCK_HEADER_POST;
    entrySep = OUTPUT_DEFAULT_ENTRY_SEP;
    entryKeyValueSep = OUTPUT_DEFAULT_ENTRY_KEY_VALUE_SEP;
    entryListSep = OUTPUT_DEFAULT_ENTRY_LIST_SEP;
}

inline void OutputUtil::addBlock(OutputBlock &block)
{
    blocks.push_back(block);
}

inline void OutputUtil::print(raw_ostream &O)
{
    for (unsigned i=0;i<blocks.size();i++) {
        if (blocks[i].size() == 0)
            continue;
        blocks[i].print(*this, O);
        O << blockSep;
    }
}

inline std::string OutputUtil::intToStr(long v)
{
    std::string string;
    raw_string_ostream ostream(string);
    ostream << v;
    ostream.flush();
    return string;
}

inline std::string OutputUtil::uintToStr(unsigned long v)
{
    std::string string;
    raw_string_ostream ostream(string);
    ostream << v;
    ostream.flush();
    return string;
}

}

#endif /* _OUTPUT_COMMON_H */

