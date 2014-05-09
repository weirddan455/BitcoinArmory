#include "LSM.h"    

#include <lsm.h>

#include <sstream>

#include "BinaryData.h"

//#define DISABLE_TRANSACTIONS

#define LSM_TRACE

#ifdef LSM_TRACE
#include <fstream>
static std::map<const LSM*, unsigned> dbToIndex;
static unsigned numDbs=0;
static std::ofstream trace;

static unsigned dbNumFor(const LSM *lsm)
{
   const std::map<const LSM*, unsigned>::iterator i = dbToIndex.find(lsm);
   if (i == dbToIndex.end())
   {
      const unsigned v = numDbs++;
      dbToIndex[lsm] = v;
      return v;
   }
   else
   {
      return i->second;
   }
}

#endif



static std::string errorString(int rc)
{
   if (rc == LSM_OK)
      return "OK";
   else if (rc == LSM_ERROR)
      return "Error";
   else if (rc == LSM_BUSY)
      return "Busy";
   else if (rc == LSM_NOMEM)
      return "No Memory";
   else if (rc == LSM_IOERR)
      return "IO Error";
   else if (rc == LSM_CORRUPT)
      return "Corrupt";
   else if (rc == LSM_FULL)
      return "Full";
   else if (rc == LSM_CANTOPEN)
      return "Can't Open";
   else if (rc == LSM_PROTOCOL)
      return "Protocol";
   else if (rc == LSM_MISUSE)
      return "Misuse";
   else
      return "Unknown Error";
}

std::string toStringFormatted(const std::string &s)
{
   std::string out;
   out.reserve(s.length()*3);
   
   for (size_t i=0; i < s.size(); i++)
   {
      const unsigned char c = s[i];
      
      if (c == 0)
         out += "\\0";
      else if (std::isalnum(c))
         out += c;
      else
      {
         out += "\\x";
         if (c <= 0xf)
            out += '0';
         std::ostringstream ss;
         ss << std::hex << (unsigned)c;
         out += ss.str();
      }
   }
   return out;
}
/*
class X
{
public:
   X()
   {
      std::string hex = "4e07c7c8158d897361f24ee70efe01a1e09a0a45acf9499c0339d701202d810f";
      hex = BinaryData::CreateFromHex(hex).toBinStr();
      
      std::cout << toStringFormatted(hex);
   }
};

X x;
*/

void LSM::Iterator::reset()
{
   if (shared)
   {
      shared->sharedCount--;
      
      if (shared->sharedCount==0)
      {
#ifdef LSM_TRACE
         trace << dbNumFor(db) << " csr_close " << (void*)shared->csr
            << std::endl;
#endif
         lsm_csr_close(shared->csr);
         delete shared;
      }
   }
   db = 0;
   shared = 0;
}

inline void LSM::Iterator::checkOk() const
{
   if (!db || !shared)
   {
      throw std::logic_error("Tried to use invalid LSM Iterator");
   }
}

void LSM::Iterator::detach()
{
   if (!shared || shared->sharedCount==1)
      return;
   
   SharedCsr *another = new SharedCsr;
   try
   {
      
      if (isValid())
      {
         int rc = lsm_csr_open(db->db, &another->csr);
#ifdef LSM_TRACE
         trace << dbNumFor(db) << " csr_open " << (void*)another->csr 
            << std::endl;
#endif
         if (rc != LSM_OK)
            throw std::runtime_error("Failed to create cursor (" + errorString(rc) + ")");
            
         const void *key;
         int len;
#ifdef LSM_TRACE
         trace << dbNumFor(db) << " csr_key " << (void*)another->csr
            << std::endl;
#endif
         rc = lsm_csr_key(shared->csr, &key, &len);
         if (rc != LSM_OK)
            throw std::runtime_error("Failed to read old cursor (" + errorString(rc) + ")");
#ifdef LSM_TRACE
         trace << dbNumFor(db) << " csr_seek " << (void*)another->csr << " "
            << toStringFormatted(std::string(static_cast<const char*>(key), len))
            << " ge"
            << std::endl;
#endif
         rc = lsm_csr_seek(another->csr, key, len, LSM_SEEK_GE);
         if (rc != LSM_OK)
            throw std::runtime_error("Failed to seek new cursor (" + errorString(rc) + ")");
      }
      shared->sharedCount--;
      another->sharedCount++;
      shared = another;
   }
   catch (...)
   {
      delete another;
      throw;
   }
}

LSM::Iterator::Iterator(const LSM *db)
   : db(db)
{
   shared = new SharedCsr;
   try
   {
      int rc = lsm_csr_open(db->db, &shared->csr);
#ifdef LSM_TRACE
      trace << dbNumFor(db) << " csr_open " << (void*)shared->csr
         << std::endl;
#endif
      if (rc != LSM_OK)
         throw std::runtime_error("Failed to create cursor (" + errorString(rc) + ")");

      shared->sharedCount=1;
   }
   catch (...)
   {
      delete shared;
      shared = 0;
      throw;
   }
}

LSM::Iterator::Iterator()
{
   db = 0;
   shared = 0;
}

LSM::Iterator::~Iterator()
{
   reset();
}

LSM::Iterator::Iterator(const Iterator &copy)
{
   db = copy.db;
   shared = copy.shared;
   if (shared)
      shared->sharedCount++;
}

LSM::Iterator& LSM::Iterator::operator=(const Iterator &copy)
{
   if (this == &copy)
      return *this;
   
   reset();
   db = copy.db;
   shared = copy.shared;
   if (shared)
      shared->sharedCount++;
   return *this;
}

bool LSM::Iterator::operator==(const Iterator &other) const
{
   if (this == &other)
      return true;

   {
      bool a = isEOF();
      bool b = other.isEOF();
      if (a && b) return true;
      if (a || b) return false;
   }
   
   return key() == other.key();
}

bool LSM::Iterator::isValid() const
{
   if (!shared) return false;
#ifdef LSM_TRACE
   trace << dbNumFor(db) << " csr_valid " << (void*)shared->csr 
      << std::endl;
#endif
   return !!lsm_csr_valid(shared->csr);
}

void LSM::Iterator::advance()
{
   checkOk();
   detach();
#ifdef LSM_TRACE
   trace << dbNumFor(db) << " csr_next " << (void*)shared->csr 
      << std::endl;
#endif
   int rc = lsm_csr_next(shared->csr);
   if (rc != LSM_OK)
      throw std::runtime_error("Failed to advance cursor (" + errorString(rc) + ")");
}
/*
void LSM::Iterator::advance(int c)
{
   checkOk();
   detach();
   while (c--)
   {
#ifdef LSM_TRACE
   trace << dbNumFor(db) << " csr_next " << (void*)shared->csr 
      << std::endl;
#endif
      lsm_csr_next(shared->csr);
   }
}
*/
void LSM::Iterator::toFirst()
{
   checkOk();
   detach();
#ifdef LSM_TRACE
   trace << dbNumFor(db) << " csr_first " << (void*)shared->csr 
      << std::endl;
#endif
   int rc = lsm_csr_first(shared->csr);
   if (rc != LSM_OK)
      throw std::runtime_error("Failed to seek cursor to first (" + errorString(rc) + ")");
}

void LSM::Iterator::seek(const CharacterArrayRef &key, SeekBy e)
{
   checkOk();
   detach();
   const char *ds="?";
   int le = LSM_SEEK_GE;
   if (e == Seek_EQ)
   {
      ds = "ge";
      le = LSM_SEEK_GE;
   }
   else if (e == Seek_LE)
   {
      ds = "le";
      le = LSM_SEEK_LE;
   }
   else if (e == Seek_GE)
   {
      ds = "ge";
      le = LSM_SEEK_GE;
   }
   
#ifdef LSM_TRACE
   trace << dbNumFor(db) << " csr_seek " << (void*)shared->csr << " "
      << toStringFormatted(std::string(key.data, key.len))
      << " " << ds
      << std::endl;
#endif
   int rc = lsm_csr_seek(shared->csr, key.data, key.len, le);
   if (rc != LSM_OK)
      throw std::runtime_error("Failed to seek cursor (" + errorString(rc) + ")");
   
   if (e == Seek_EQ)
   {
#ifdef LSM_TRACE
      trace << dbNumFor(db) << " csr_cmp " << (void*)shared->csr << " "
         << toStringFormatted(std::string(key.data, key.len))
         << std::endl;
#endif
      int r;
      // advance() doesn't work if we don't use SEEK_GE, so we always do
      lsm_csr_cmp(shared->csr, key.data, key.len, &r);
      if (r != 0)
      {
#ifdef LSM_TRACE
         trace << dbNumFor(db) << " csr_seek " << (void*)shared->csr << " "
            << toStringFormatted(std::string(key.data, key.len))
            << " eq"
            << std::endl;
#endif
         // invalidate the search if we don't match
         lsm_csr_seek(shared->csr, key.data, key.len, LSM_SEEK_EQ);
      }
   }
}

std::string LSM::Iterator::key() const
{
   checkOk();
   const void *key;
   int len;
#ifdef LSM_TRACE
   trace << dbNumFor(db) << " csr_key " << (void*)shared->csr
      << std::endl;
#endif
   int rc = lsm_csr_key(shared->csr, &key, &len);
   if (rc != LSM_OK)
      throw std::runtime_error("Failed to read cursor key (" + errorString(rc) + ")");
   return std::string(static_cast<const char*>(key), len);
}

std::string LSM::Iterator::value() const
{
   checkOk();
   const void *val;
   int len;
#ifdef LSM_TRACE
   trace << dbNumFor(db) << " csr_value " << (void*)shared->csr
      << std::endl;
#endif
   int rc = lsm_csr_value(shared->csr, &val, &len);
   if (rc != LSM_OK)
      throw std::runtime_error("Failed to read cursor value (" + errorString(rc) + ")");
   return std::string(static_cast<const char*>(val), len);
}


LSM::Transaction::Transaction(LSM *db)
   : db(db), myLevel(-1)
{
   begin();
}

LSM::Transaction::~Transaction()
{
   commit();
}

void LSM::Transaction::commit()
{
   if (myLevel == -1)
      return;
   if (myLevel != db->transactionLevel-1)
      throw std::runtime_error("Cannot commit the non topmost transaction");
   
#ifndef DISABLE_TRANSACTIONS
#ifdef LSM_TRACE
   trace << dbNumFor(db) << " commit " << myLevel << std::endl;
#endif
   int rc = lsm_commit(db->db, myLevel);
   
   if (rc != LSM_OK)
      throw std::runtime_error("Failed to commit transaction (" + errorString(rc) + ")");
#endif
   myLevel = -1;
   db->transactionLevel--;

}
void LSM::Transaction::rollback()
{
   if (myLevel == -1)
      return;
   if (myLevel != db->transactionLevel-1)
      throw std::runtime_error("Cannot rollback the non topmost transaction");
   
#ifndef DISABLE_TRANSACTIONS
#ifdef LSM_TRACE
   trace << dbNumFor(db) << " rollback " << myLevel << std::endl;
#endif
   int rc = lsm_rollback(db->db, myLevel);
   
   if (rc != LSM_OK)
      throw std::runtime_error("Failed to rollback transaction (" + errorString(rc) + ")");
#endif
   myLevel = -1;
   db->transactionLevel--;
}

void LSM::Transaction::begin()
{
   if (myLevel != -1)
      return;
   
   myLevel = db->transactionLevel++;
#ifndef DISABLE_TRANSACTIONS
#ifdef LSM_TRACE
   trace << dbNumFor(db) << " begin " << (myLevel+1) << std::endl;
#endif

   int rc = lsm_begin(db->db, myLevel+1);
   if (rc != LSM_OK)
   {
      myLevel = -1;
      db->transactionLevel--;
      throw std::runtime_error("Failed to begin transaction (" + errorString(rc) + ")");
   }
#endif
}


LSM::LSM()
{
   db = 0;
   thread = 0;
}

LSM::~LSM()
{
   close();
}

void LSM::open(const char *filename)
{
   if (db)
      throw std::logic_error("Database object already open (close it first)");

   transactionLevel=0;
   int rc;
   
   rc = lsm_new(lsm_default_env(), &db);
   if (rc != LSM_OK)
      throw LSMException("Failed to load LSM (" + errorString(rc) + ")");

   rc = lsm_open(db, filename);
   if (rc != LSM_OK)
      throw LSMException("Failed to open " + std::string(filename)
         + " ("+ errorString(rc) + ")");

#ifdef LSM_THREADCHECK
   thread = pthread_self();
#endif
#ifdef LSM_TRACE
   if (!trace.is_open())
   {
      trace.open( (filename + std::string(".trace")).c_str(), std::ios::app);
   }
   trace << dbNumFor(this) << " open" << std::endl;
#endif
}

void LSM::close()
{
   if (db)
   {
#ifdef LSM_TRACE
      trace << dbNumFor(this) << " close" << std::endl;
#endif
      int rc = lsm_close(db);
      if (rc != LSM_OK)
      {
         throw LSMException(
            "LSM failed to close, probably a transaction or database cursor still open ("
            + errorString(rc) + ")"
         );
      }
      db = 0;
      thread = 0;
   }
}

void LSM::insert(
   const CharacterArrayRef& key,
   const CharacterArrayRef& value
)
{
#ifdef LSM_THREADCHECK
   if (!pthread_equal(thread, pthread_self()))
      throw std::runtime_error("Used LSM on two threads");
#endif
#ifdef LSM_TRACE
   trace << dbNumFor(this) << " insert "
      << toStringFormatted(std::string(static_cast<const char*>(key.data), key.len))
      << " "
      << toStringFormatted(std::string(static_cast<const char*>(value.data), value.len))
      << std::endl;
#endif

   int rc = lsm_insert(db, key.data, key.len, value.data, value.len);
   if (rc != LSM_OK)
      throw LSMException("Failed to insert (" + errorString(rc) + ")");
}

void LSM::erase(const CharacterArrayRef& key)
{
#ifdef LSM_THREADCHECK
   if (!pthread_equal(thread, pthread_self()))
      throw std::runtime_error("Used LSM on two threads");
#endif
#ifdef LSM_TRACE
   trace << dbNumFor(this) << " delete "
      << toStringFormatted(std::string(static_cast<const char*>(key.data), key.len))
      << std::endl;
#endif
   int rc = lsm_delete(db, key.data, key.len);
   if (rc != LSM_OK)
      throw LSMException("Failed to erase (" + errorString(rc) + ")");

}

void LSM::eraseBetween(
   const CharacterArrayRef& key1,
   const CharacterArrayRef& key2
)
{
#ifdef LSM_THREADCHECK
   if (!pthread_equal(thread, pthread_self()))
      throw std::runtime_error("Used LSM on two threads");
#endif
#ifdef LSM_TRACE
   trace << dbNumFor(this) << " delete_range "
      << toStringFormatted(std::string(static_cast<const char*>(key1.data), key1.len))
      << toStringFormatted(std::string(static_cast<const char*>(key2.data), key2.len))
      << std::endl;
#endif
   int rc = lsm_delete_range(db, key1.data, key1.len, key2.data, key2.len);
   if (rc != LSM_OK)
      throw LSMException("Failed to erase range (" + errorString(rc) + ")");
}

std::string LSM::value(const CharacterArrayRef& key) const
{
#ifdef LSM_THREADCHECK
   if (!pthread_equal(thread, pthread_self()))
      throw std::runtime_error("Used LSM on two threads");
#endif
   Iterator c = cursor();
   c.seek(key);
   if (!c.isValid())
      throw std::runtime_error("No such value with specified key");
   return c.value();
}

// kate: indent-width 3; replace-tabs on;
