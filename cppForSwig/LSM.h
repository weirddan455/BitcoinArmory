#ifndef _LSM_HPP
#define _LSM_HPP

#include <string>
#include <stdexcept>
#include <vector>
#include <pthread.h>



//#define LSM_THREADCHECK

std::string toStringFormatted(const std::string &s);

// this exception is thrown for all errors from LSM
class LSMException : public std::runtime_error
{
public:
   LSMException(const std::string &what)
      : std::runtime_error(what)
   { }
};

class NoValue : public LSMException
{
public:
   NoValue(const std::string &what)
      : LSMException(what)
   { }
};


// a class that stores a pointer to a memory block
class CharacterArrayRef
{
public:
   const size_t len;
   const char *data;
   
   CharacterArrayRef(const size_t len, const char *data)
      : len(len), data(data)
   { }
   CharacterArrayRef(const size_t len, const unsigned char *data)
      : len(len), data(reinterpret_cast<const char*>(data))
   { }
   CharacterArrayRef(const std::string &data)
      : len(data.size()), data(&data[0])
   { }
   CharacterArrayRef(const std::vector<char> &data)
      : len(data.size()), data(&data.front())
   { }
};


class LSM
{
   void *db, *env;
   unsigned transactionLevel;
   pthread_t thread;
public:
   // this class can be used like a C++ iterator,
   // or you can just use isValid() to test for "last item"
   class Iterator
   {
      friend class LSM;
      
      const LSM *db;
      // this complexity is caused because we want
      // returning Cursors to be real fast. We could
      // remove it in C++11 with Move operators
      struct SharedCsr
      {
         void *csr;
         // the number of Iterator objects point to this SharedCsr
         unsigned sharedCount;
         SharedCsr()
            : csr(0), sharedCount(1)
         { }
      };
      
      SharedCsr *shared;
      
      void reset();
      void checkHasDb() const;
      void checkOk() const;
      void detach();
      
      Iterator(const LSM *db);
      
   public:
      Iterator();
      ~Iterator();
      
      // copying permitted (encouraged!)
      Iterator(const Iterator &copy);
      Iterator& operator=(const Iterator &copy);
      
      // Returns true if the key pointed to is identical, or if both iterators
      // are invalid, and false otherwise.
      // returns true if the key pointed to is in different databases
      bool operator==(const Iterator &other) const;
      // the inverse
      bool operator!=(const Iterator &other) const
      {
         return !operator==(other);
      }
      
      enum SeekBy
      {
         Seek_GE
      };
      
      // move this iterator such that, if the exact key is not found:
      // for e == Seek_EQ
      // The cursor is left as Invalid.
      // for e == Seek_LE
      // The cursor is left pointing to the largest key in the database that is
      // smaller than (jeu). If the database contains no keys smaller than
      // (key), the cursor is left as Invalid.
      // LSM_SEEK_GE
      // The cursor is left pointing to the smallest key in the database that is
      // larger than (key). If the database contains no keys larger than
      // (key), the cursor is left as Invalid.
      //
      // Implementation detail: Seek_EQ in this class is not
      // functionally identical to LSM_SEEK_EQ - LSM_SEEK_EQ's iterator
      // cannot be advanced, but Seek_EQ can.
      void seek(const CharacterArrayRef &key, SeekBy e = Seek_GE);
      
      // is the cursor pointing to a valid location?
      bool isValid() const { return !!shared; }
      operator bool() const { return isValid(); }
      bool isEOF() const { return !isValid(); }

      // advance the cursor
      // the postfix increment operator is not defined for performance reasons
      Iterator& operator++() { advance(); return *this; }
      void advance();
      // advance this iterator "count" times
      //void advance(int count);
      
      // seek this iterator to the first sequence
      void toFirst();
      
      // returns the key currently pointed to, if no key is being pointed to
      // std::logic_error is returned (not LSMException). LSMException may
      // be thrown for other reasons. You can avoid logic_error by
      // calling isValid() first
      std::string key() const;
      
      // returns the value currently pointed to. Exceptions are thrown
      // under the same conditions as key()
      std::string value() const;
   };
   
   class Transaction
   {
      LSM *db;
      unsigned myLevel;
   public:
      // begin a transaction
      Transaction(LSM *db);
      // commit a transaction if it exists
      ~Transaction();
      
      // commit a transaction, if it exists, doing nothing otherwise.
      // after this function completes, no transaction exists
      void commit();
      // rollback the transaction, if it exists, doing nothing otherwise.
      // All modifications made since this transaction began are removed.
      // After this function completes, no transaction exists
      void rollback();
      // start a new transaction. If one already exists, do nothing
      void begin();
   private:
      Transaction(const Transaction&); // no copies
   };

   LSM();
   ~LSM();
   
   // open a database by filename
   void open(const char *filename);
   void open(const std::string &filename) { open(filename.c_str()); }

   // close a database, doing nothing if one is presently not open
   void close();
   
   // insert a value into the database, replacing
   // the one with a matching key if it is already there
   void insert(
      const CharacterArrayRef& key,
      const CharacterArrayRef& value
   );
   
   // delete the entry with the given key, doing nothing
   // if such a key does not exist
   void erase(const CharacterArrayRef& key);

   // read the value having the given key
   std::string value(const CharacterArrayRef& key) const;
   
   // create a cursor for scanning the database that points to the first
   // item
   Iterator begin() const
   {
#ifdef LSM_THREADCHECK
      if (!pthread_equal(thread, pthread_self()))
         throw std::runtime_error("Used LSM on two threads");
#endif
      Iterator c(this);
      c.toFirst();
      return c;
   }
   // creates a cursor that points to an invalid item
   Iterator end() const
   {
#ifdef LSM_THREADCHECK
      if (!pthread_equal(thread, pthread_self()))
         throw std::runtime_error("Used LSM on two threads");
#endif
      Iterator c(this);
      return c;
   }
   
   // Create an iterator that points to an invalid item.
   // like end(), the iterator can be repositioned to
   // become a valid entry
   Iterator cursor() const { return end(); }
};

#endif
// kate: indent-width 3; replace-tabs on;

