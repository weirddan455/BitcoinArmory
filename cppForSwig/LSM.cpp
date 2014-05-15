#include "LSM.h"    

#include <sophia.h>

#include <sstream>

#include "BinaryData.h"

//#define DISABLE_TRANSACTIONS

//#define LSM_TRACE

#ifdef LSM_TRACE
#include <fstream>
unsigned traceNum=0;
unsigned numOpen=0;
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
   const char *s = sp_error(env);
   return s ? s : "Unknown error";
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

LSM::Iterator::Iterator(const LSM *db)
   : db(db), has_(false)
{

}

LSM::Iterator::Iterator()
{
   db = 0;
   has_ = false;
}

LSM::Iterator::~Iterator()
{
}

LSM::Iterator::Iterator(const Iterator &copy)
{
   db = copy.db;
   key_ = copy.key_;
   val_ = copy.val_;
   has_ = copy.has_;
}

LSM::Iterator& LSM::Iterator::operator=(const Iterator &copy)
{
   if (this == &copy)
      return *this;
   
   db = copy.db;
   key_ = copy.key_;
   val_ = copy.val_;
   has_ = copy.has_;
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
   seek(CharacterArrayRef(key_.length(), key_.data()), Seek_GT);
}

void LSM::Iterator::toFirst()
{
   checkHasDb();
   seek(CharacterArrayRef(0, (char*)0), Seek_GE);
}

void LSM::Iterator::seek(const CharacterArrayRef &key, SeekBy e)
{
   checkHasDb();
   has_ = false;
   
   sporder order = SPGTE;
   if (e == Seek_GT)
      order = SPGT;
   
   void *csr = sp_cursor(db->db, order, key.data, key.len);
   if (!csr)
      throw LSMException("failed to open cursor (" + errorString(db->db) + ")");
   
   int rc = sp_fetch(csr);
   if (rc == 1)
   {
      const char *key = sp_key(csr);
      size_t keysize = sp_keysize(csr);
      key_ = std::string(key, keysize);
      const char *val = sp_value(csr);
      size_t valsize = sp_valuesize(csr);
      val_ = std::string(val, valsize);
      has_ = true;
   }
   else if (rc == -1)
   {
      sp_destroy(csr);
      throw LSMException("Faild to fetch cursor data");
   }
   
   sp_destroy(csr);
}

std::string LSM::Iterator::key() const
{
   checkOk();
   return key_;
}

std::string LSM::Iterator::value() const
{
   checkOk();
   return val_;
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

   if (myLevel == 1)
   {
      int rc = sp_commit(db->db);
      
      if (rc == -1)
         throw std::runtime_error("Failed to commit transaction (" + errorString(db->env) + ")");
      myLevel = 0;
   }
}
void LSM::Transaction::rollback()
{
   if (myLevel == 0)
      return;
   
   throw std::runtime_error("unimplemented");
   if (myLevel != 1)
      throw std::runtime_error("Cannot rollback the non-deepest transaction");
   
   if (myLevel == 1)
   {
      int rc = sp_rollback(db->db);
   
      if (rc == -1)
         throw std::runtime_error("Failed to rollback transaction (" + errorString(db->env) + ")");
      myLevel = 0;
   }
   myLevel = 0;
   db->transactionLevel--;
}

void LSM::Transaction::begin()
{
   if (myLevel != 0)
      return;
   
   myLevel = ++db->transactionLevel;

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
#ifdef LSM_TRACE
   numOpen++;
   if (!trace.is_open())
   {
      std::ostringstream ss;
      ss << "/tmp/sophia.trace." << (traceNum++);
      trace.open(ss.str().c_str());
   }
#endif

   if (env)
      throw std::logic_error("Database object already open (close it first)");

   transactionLevel=0;
   
   env = sp_env();
   if (!env)
      throw LSMException("Failed to load sp env");
   
   int rc;
   
   rc = sp_ctl(env, SPDIR, SPO_CREAT|SPO_RDWR, filename);
   if (rc == -1)
      throw LSMException("Failed to load LSM (" + errorString(env) + ")");

#ifdef LSM_TRACE
   trace << dbNumFor(this) << " open "
      << std::endl;
#endif
   db = sp_open(env);
   
   if (!db)
   {
      sp_destroy(env);
      env = 0;
      throw LSMException("Failed to open " + std::string(filename)
         + " ("+ errorString(env) + ")");
   }
}

void LSM::close()
{
   if (db)
   {
      int rc;
#ifdef LSM_TRACE
      trace << dbNumFor(this) << " close "
         << std::endl;
#endif
      rc = sp_destroy(db);
      if (rc == -1)
         throw LSMException("LSM failed to close");
      rc = sp_destroy(env);
      if (rc == -1)
         throw LSMException("LSM failed to destroy env");
      db = 0;
      env = 0;
      thread = 0;
   }

#ifdef LSM_TRACE
   numOpen--;
   if (numOpen==0)
      trace.close();
#endif
}

void LSM::insert(
   const CharacterArrayRef& key,
   const CharacterArrayRef& value
)
{
   int rc = sp_set(db, key.data, key.len, value.data, value.len);
   if (rc == -1)
      throw LSMException("Failed to insert (" + errorString(env) + ")");
}

void LSM::erase(const CharacterArrayRef& key)
{
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
   void* res;
   size_t rs;
#ifdef LSM_TRACE
   trace << dbNumFor(this) << " get "
      << toStringFormatted(std::string(static_cast<const char*>(key.data), key.len))
      << std::endl;
#endif
   
   int rc = sp_get(db, key.data, key.len, &res, &rs);

   if (rc == 0)
      throw NoValue("No such value with specified key");
   else if (rc == -1)
      throw LSMException("Failed to search (" + errorString(env) + ")");

   std::string s(static_cast<char*>(res), rs);
   free(res);
   return s;
}

// kate: indent-width 3; replace-tabs on;
