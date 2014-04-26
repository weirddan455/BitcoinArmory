#include "LSM.h"

#include <stdio.h>

#include <sstream>
#include <iostream>
#include <cctype>
#include <cstdlib>

#include <readline/readline.h>
#include <readline/history.h>

static unsigned hexValue(char c)
{
   if (c >= '0' && c <= '9')
      return unsigned(c)-'0';
   else if (c >= 'a' && c <= 'f')
      return unsigned(c)-'a' + 0xa;
   else if (c >= 'A' && c <= 'F')
      return unsigned(c)-'A' + 0xa;
   
   char x[2] = { c, 0 };
   throw std::runtime_error("Not a valid hex character " + std::string(x));
}

static std::string toStringEncoded(const std::string &d)
{
   std::string s;
   s.reserve(d.length()*3);
   
   for (size_t i=0; i < d.length(); i++)
   {
      const unsigned char c = d[i];
      
      if (isalnum(c))
      {
         s += c;
      }
      else if (c == 0)
         s += "\\0";
      else
      {
         s += "\\x";
         std::ostringstream ss;
         if (unsigned(c) < 0x10)
            ss << "0";
         ss << std::hex;
         ss << unsigned(c);
         s += ss.str();
      }
   }
   return s;
}

static std::string fromStringEncoded(const std::string &s)
{
   std::string o;
   o.reserve(s.length());
   
   enum State
   {
      Normal,
      Slashie,
      Hex1, Hex2
   };
   State state = Normal;
   
   char byte;
   
   for (size_t i=0; i < s.length(); i++)
   {
      try
      {
         const char c = s[i];
         
         if (state == Normal)
         {
            if (c == '\\')
               state = Slashie;
            else
               o += c;
         }
         else if (state == Slashie)
         {
            state = Normal;
            if (c == '\\')
               o += '\\';
            else if ( c == 'x')
               state = Hex1;
            else if (c == '0')
               o += '\0';
         }
         else if (state == Hex1)
         {
            byte = hexValue(c);
            state = Hex2;
         }
         else if (state == Hex2)
         {
            byte <<= 4;
            byte |= hexValue(c);
            o += byte;
            state = Normal;
         }
      }
      catch (std::exception &e)
      {
         std::ostringstream ss;
         ss << i;
         throw std::runtime_error("Error at string offset " + ss.str() + ": " + e.what());
      }
   }
   
   if (state != Normal)
   {
      throw std::runtime_error("Unexpected end of string");
   }
   return o;
}

int main(int argc, char **argv)
{
   if (argc != 2)
   {
      std::cerr << "No file specified" << std::endl;
      return 1;
   }
   
   LSM lsm;
   lsm.open(argv[1]);
   
   std::string lastcommand="";
   
   LSM::Iterator it;
   
   std::vector<LSM::Transaction*> transactions;
   
   while (char *_line = readline("lsm> "))
   {
      try
      {
         std::string l(_line);
         if (l.length())
            add_history(_line);
         std::free(_line);
         
         bool doprint=true;
         if (l == "")
            l = lastcommand;
         
         if (l == "help" || l == "h")
         {
            std::cout << "help, h    this stuff\n";
            std::cout << "first,f    point to the first element, print it\n";
            std::cout << "next,n     advance the cursor, print it\n";
            std::cout << "p          print the current cursor\n";
            std::cout << "s <data>   search for a key >= data\n";
            std::cout << "c          Count entries in the database\n";
            std::cout << "begin      Start a (nested) transaction\n";
            std::cout << "commit     Commit the top transaction\n";
            std::cout << std::flush;
            continue;
         }
         else if ( l == "q" || l == "quit")
            break;
         else if ( l =="first" || l == "f")
         {
            it = lsm.begin();
         }
         else if ( l =="c")
         {
            LSM::Iterator it = lsm.begin();
            unsigned c=0;
            while (it.isValid())
            {
               c++;
               ++it;
            }
            std::cout << c << " entries" << std::endl;
            doprint=false;
         }
         else if ( l =="next" || l == "n")
         {
            if (it.isEOF())
            {
               std::cerr << "Cursor not set" << std::endl;
               continue;
            }
            ++it;
            if (!it.isValid())
            {
               std::cout << "(Reached end)" << std::endl;
               continue;
            }
         }
         else if ( l == "p" || l == "print")
         {
            // nothing
         }
         else if ( l.length() > 3 && l[0] == 's' && std::isspace(l[1]))
         {
            std::string s = fromStringEncoded(l.substr(2));
            it = lsm.cursor();
            it.seek(s, LSM::Iterator::Seek_GE);
         }
         else if ( l == "begin" )
         {
            transactions.push_back( new LSM::Transaction(&lsm) );
            std::cout << "Now inside " << transactions.size() << " transactions" << std::endl;
            doprint=false;
         }
         else if ( l == "commit" )
         {
            if (transactions.empty())
            {
               std::cout << "No transactions" << std::endl;
            }
            else
            {
               delete transactions.back();
               transactions.pop_back();
               std::cout << "Now inside " << transactions.size() << " transactions" << std::endl;
            }
            doprint=false;
         }
         else
         {
            std::cout << "No command '" << l << "'" << std::endl;
         }
         
         if (it.isValid() && doprint)
         {
            std::cout << "    key=\"" << toStringEncoded(it.key()) << "\"" << std::endl;
            std::cout << "    val=\"" << toStringEncoded(it.value()) << "\"" << std::endl;
         }
         
         lastcommand = l;
      }
      catch (std::exception &e)
      {
         std::cerr << "error: " << e.what() << std::endl;
      }
   }
   return 0;
}


// kate: indent-width 3; replace-tabs on;
