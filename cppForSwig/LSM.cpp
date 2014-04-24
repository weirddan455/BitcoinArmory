#include "LSM.h"

#include <lsm.h>

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

void LSM::Iterator::reset()
{
   if (shared)
   {
      shared->sharedCount--;
      
      if (shared->sharedCount==0)
      {
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
         int rc = lsm_csr_open(db, &another->csr);
         if (rc != LSM_OK)
            throw std::runtime_error("Failed to create cursor (" + errorString(rc) + ")");
            
            
         const void *key;
         int len;
         rc = lsm_csr_key(shared->csr, &key, &len);
         if (rc != LSM_OK)
            throw std::runtime_error("Failed to read old cursor (" + errorString(rc) + ")");
         rc = lsm_csr_seek(another->csr, key, len, LSM_SEEK_EQ);
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

LSM::Iterator::Iterator(lsm_db *db)
   : db(db)
{
   shared = new SharedCsr;
   try
   {
      int rc = lsm_csr_open(db, &shared->csr);
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
   checkOk();
   return !!lsm_csr_valid(shared->csr);
}

void LSM::Iterator::advance()
{
   checkOk();
   detach();
   int rc = lsm_csr_next(shared->csr);
   if (rc != LSM_OK)
      throw std::runtime_error("Failed to advance cursor (" + errorString(rc) + ")");
}
void LSM::Iterator::advance(int c)
{
   checkOk();
   detach();
   while (c--)
   {
      lsm_csr_next(shared->csr);
   }
}

void LSM::Iterator::toFirst()
{
   checkOk();
   detach();
   int rc = lsm_csr_first(shared->csr);
   if (rc != LSM_OK)
      throw std::runtime_error("Failed to seek cursor to first (" + errorString(rc) + ")");
}

void LSM::Iterator::seek(const CharacterArrayRef &key, SeekBy e)
{
   checkOk();
   detach();
   int le = LSM_SEEK_GE;
   if (e == Seek_EQ)
      le = LSM_SEEK_GE;
   else if (e == Seek_LE)
      le = LSM_SEEK_LE;
   else if (e == Seek_GE)
      le = LSM_SEEK_GE;
   
   
   int rc = lsm_csr_seek(shared->csr, key.data, key.len, le);
   if (rc != LSM_OK)
      throw std::runtime_error("Failed to seek cursor (" + errorString(rc) + ")");
   
   if (e == Seek_EQ)
   {
      int r;
      // advance() doesn't work if we don't use SEEK_GE, so we always do
      lsm_csr_cmp(shared->csr, key.data, key.len, &r);
      if (r != 0)
      {
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
   
   int rc = lsm_commit(db->db, myLevel);
   
   if (rc != LSM_OK)
      throw std::runtime_error("Failed to commit transaction (" + errorString(rc) + ")");
   myLevel = -1;
   db->transactionLevel--;

}
void LSM::Transaction::rollback()
{
   if (myLevel == -1)
      return;
   if (myLevel != db->transactionLevel-1)
      throw std::runtime_error("Cannot rollback the non topmost transaction");
   
   int rc = lsm_rollback(db->db, myLevel);
   
   if (rc != LSM_OK)
      throw std::runtime_error("Failed to rollback transaction (" + errorString(rc) + ")");
   myLevel = -1;
   db->transactionLevel--;
}

void LSM::Transaction::begin()
{
   if (myLevel != -1)
      return;
   
   myLevel = db->transactionLevel++;
   int rc = lsm_begin(db->db, myLevel);
   if (rc != LSM_OK)
   {
      myLevel = -1;
      db->transactionLevel--;
      throw std::runtime_error("Failed to begin transaction (" + errorString(rc) + ")");
   }
}


LSM::LSM()
{
   db = 0;
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
}

void LSM::close()
{
   if (db)
   {
      int rc = lsm_close(db);
      if (rc != LSM_OK)
      {
         throw LSMException(
            "LSM failed to close, probably a transaction or database cursor still open ("
            + errorString(rc) + ")"
         );
      }
      db = 0;
   }
}

void LSM::insert(
   const CharacterArrayRef& key,
   const CharacterArrayRef& value
)
{
   int rc = lsm_insert(db, key.data, key.len, value.data, value.len);
   if (rc != LSM_OK)
      throw LSMException("Failed to insert (" + errorString(rc) + ")");
}

void LSM::erase(const CharacterArrayRef& key)
{
   int rc = lsm_delete(db, key.data, key.len);
   if (rc != LSM_OK)
      throw LSMException("Failed to erase (" + errorString(rc) + ")");

}

void LSM::eraseBetween(
   const CharacterArrayRef& key1,
   const CharacterArrayRef& key2
)
{
   int rc = lsm_delete_range(db, key1.data, key1.len, key2.data, key2.len);
   if (rc != LSM_OK)
      throw LSMException("Failed to erase range (" + errorString(rc) + ")");
}

std::string LSM::value(const CharacterArrayRef& key) const
{
   Iterator c = cursor();
   c.seek(key);
   if (!c.isValid())
      throw std::runtime_error("No such value with specified key");
   return c.value();
}

// kate: indent-width 3; replace-tabs on;
