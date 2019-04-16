/******************************
* Author : Koustubha Bhat
* Date   : 13-Feb-2015
* Vrije Universiteit, Amsterdam.
*******************************/
#ifndef INPUT_COMMON_H
#define INPUT_COMMON_H

#include <fstream>

using namespace llvm;

namespace llvm
{

class InputLoader
{
public:
  InputLoader(Regex *lineRegex);
  bool accept(std::string line);
  unsigned read(std::string fileName);

protected:
  Regex *lineRegex;
  std::vector<std::string> acceptedLines;
};

InputLoader::InputLoader(Regex *lineRegex)
{
  std::string error;
  if (false == lineRegex->isValid(error))
  {
    DEBUG(errs() << "WARNING: The regex is invalid: " << error << "\n");
    return;
  }
  this->lineRegex = lineRegex;
}

bool InputLoader::accept(std::string line)
{
  if (NULL == lineRegex)
  {
    return false;
  }
  if (!lineRegex->match(line, NULL))
  {
    DEBUG(errs() << "Didn't match regex: " << line << "\n");
    return false;
  }
  this->acceptedLines.push_back(line);
  return true;
}

unsigned InputLoader::read(std::string fileName)
{
  std::string line = "";
  unsigned numLinesAccepted = 0;

  if ("" == fileName)
  {
    errs() << "Filename or the InputLoader are invalid.\n";
    return 0;
  }
  std::ifstream file(fileName.c_str());
  if (!file)
  {
    errs() << "WARNING: Functions list file : " << fileName << " does not exist.\n";
    return 0;
  }

  while(std::getline(file, line))
  {
    if (0 == line.length())
    {
      continue;
    }
    if (false == this->accept(line))
    {
      DEBUG(errs() << "Didn't accept: " << line << "\n");
      continue;
    }
    numLinesAccepted++;
  }
  file.close();
  return numLinesAccepted;
}


}
#endif
