#include "LSM.h"    

#include <sophia.h>

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



static std::string errorString(void *env)
{
   return sp_error(env);
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

void LSM::Iterator::reset()
{
   if (shared)
   {
      shared->sharedCount--;
      
      if (shared->sharedCount==0)
      {
         sp_destroy(shared->csr);
         delete shared;
      }
   }
   shared = 0;
}

inline void LSM::Iterator::checkHasDb() const
{
   if (!db)
   {
      throw std::logic_error("Iterator is not associated with a db");
   }
}


inline void LSM::Iterator::checkOk() const
{
   if (!isValid())
   {
      throw NoValue("Tried to use invalid LSM Iterator");
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
         throw std::logic_error("unimplemented");
      }
      shared->sharedCount--;
      shared = another;
   }
   catch (...)
   {
      delete another;
      throw;
   }
}

LSM::Iterator::Iterator(const LSM *db)
   : db(db), shared(0)
{

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

void LSM::Iterator::advance()
{
   checkOk();
   detach();
   
#ifdef LSM_TRACE
   trace << dbNumFor(db) << " csr_next " << (void*)shared->csr 
      << std::endl;
#endif
   int rc = sp_fetch(shared->csr);
   if (rc == 0)
   {
      reset();
   }
}

void LSM::Iterator::toFirst()
{
   checkHasDb();
   reset();
   seek(CharacterArrayRef(0, (char*)0), Seek_GE);
}

void LSM::Iterator::seek(const CharacterArrayRef &key, SeekBy e)
{
   checkHasDb();
   reset();
   shared = new SharedCsr;
   
   shared->csr = sp_cursor(db->db, SPGTE, key.data, key.len);
   if (!shared->csr)
   {
      LSMException e("Failed to open cursor " + errorString(db->env));
      reset();
      throw e;
   }
   
   int rc = sp_fetch(shared->csr);
   if (rc == 0)
   {
      // no value found
      reset();
   }
}

std::string LSM::Iterator::key() const
{
   checkOk();
   const char *key = sp_key(shared->csr);
   size_t keysize = sp_keysize(shared->csr);
   
   return std::string(key, keysize);
}

std::string LSM::Iterator::value() const
{
   checkOk();
   const char *value = sp_value(shared->csr);
   size_t valuesize = sp_valuesize(shared->csr);
   
   return std::string(value, valuesize);
}


LSM::Transaction::Transaction(LSM *db)
   : db(db), myLevel(0)
{
   begin();
}

LSM::Transaction::~Transaction()
{
   commit();
}

void LSM::Transaction::commit()
{
   if (myLevel == 0)
      return;
   if (myLevel != db->transactionLevel)
      throw std::runtime_error("Cannot commit the non topmost transaction");

   if (myLevel == 1)
   {
#ifndef DISABLE_TRANSACTIONS
#ifdef LSM_TRACE
      trace << dbNumFor(db) << " commit " << myLevel << std::endl;
#endif
      int rc = sp_commit(db->db);
      
      if (rc == -1)
         throw std::runtime_error("Failed to commit transaction (" + errorString(db->env) + ")");
#endif
      myLevel = 0;
   }
   db->transactionLevel--;
}
void LSM::Transaction::rollback()
{
   if (myLevel == 0)
      return;
   if (myLevel != 1)
      throw std::runtime_error("Cannot rollback the non-deepest transaction");
   
   if (myLevel == 1)
   {
#ifndef DISABLE_TRANSACTIONS
#ifdef LSM_TRACE
      trace << dbNumFor(db) << " rollback " << myLevel << std::endl;
#endif
      int rc = sp_rollback(db->db);
   
      if (rc == -1)
         throw std::runtime_error("Failed to rollback transaction (" + errorString(db->env) + ")");
#endif
      myLevel = 0;
   }
   db->transactionLevel--;
}

void LSM::Transaction::begin()
{
   if (myLevel != 0)
      return;
   
   myLevel = ++db->transactionLevel;
#ifndef DISABLE_TRANSACTIONS

   if (myLevel == 1)
   {
#ifdef LSM_TRACE
      trace << dbNumFor(db) << " begin " << myLevel << std::endl;
#endif
      int rc = sp_begin(db->db);
      if (rc == -1)
      {
         myLevel = 0;
         db->transactionLevel--;
         throw std::runtime_error("Failed to begin transaction (" + errorString(db->env) + ")");
      }
   }
#endif
}


LSM::LSM()
{
   env = 0;
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
   
   env = sp_env();
   if (!env)
      throw LSMException("Failed to load sp env");
   
   int rc;
   
   rc = sp_ctl(env, SPDIR, SPO_CREAT|SPO_RDWR, filename);
   if (rc == -1)
      throw LSMException("Failed to load LSM (" + errorString(env) + ")");

   db = sp_open(env);
   
   if (!db)
      throw LSMException("Failed to open " + std::string(filename)
         + " ("+ errorString(env) + ")");

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
      int rc;
      rc = sp_destroy(db);
      if (rc == -1)
         throw LSMException("LSM failed to close");
      rc = sp_destroy(env);
      if (rc == -1)
         throw LSMException("LSM failed to destroy env");
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

   int rc = sp_set(db, key.data, key.len, value.data, value.len);
   if (rc == -1)
      throw LSMException("Failed to insert (" + errorString(env) + ")");
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
   int rc = sp_delete(db, key.data, key.len);
   if (rc == -1)
      throw LSMException("Failed to erase (" + errorString(env) + ")");

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
      throw NoValue("No such value with specified key");
   if (c.key() !=  std::string(key.data, key.len))
      throw NoValue("No such value with specified key");
   
   return c.value();
}

// kate: indent-width 3; replace-tabs on;
