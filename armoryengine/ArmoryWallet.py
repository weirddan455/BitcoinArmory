

################################################################################
CRYPT_KEY_SRC = enum('MULTIPWD', 'PASSWORD', 'PARCHAIN', 'EKEYOBJ')
CRYPT_IV_SRC  = enum('STOREDIV', 'PUBKEY20')
NULLSTR8 = '\x00'*8
KNOWN_CRYPTO = {'AE256CFB': {'blocksize': 16, 'keysize': 32}, \
                'AE256CBC': {'blocksize': 16, 'keysize': 32} }

################################################################################
################################################################################
class ArmoryCryptInfo(object):
   """
   This can be attached to WalletEntries or individual pieces of data, to 
   describe how we plan to protect it.  The idea is to have a uniform way of
   specifying how to encrypt & decrypt things in the wallet file, even though
   it may require using information outside this object to apply it.

   For instance, private keys will usually be encrypted using a master key that 
   is, itself, encrypted.  The private key would simply have one of these 
   objects serialized next to it, specifying the ID (hash) of the master key
   that was used to encrypt it.  Then the calling code can go get that object
   and do what is needed for it.   

   Frequently, this encryption info will contain initialization vectors (IVs), 
   generated randomly at creation time, or references to what is to be used as
   the IV (such as using the hash160 of the addr).

   ArmoryCryptInfo objects carry four pieces of data:
         (1) KDF algorithm & params   (via ID)
         (2) Encryption algo & params (via ID)
         (3) Encryption key source
         (4) Initialization Vect source

   The examples below use the following IDs, though they would normally be
   hash of the parameters used:

         KDF object with ID      '11112222aaaabbbb'   (ROMixOver2 w/ params)
         Crypto obj with ID      'ccccdddd88889999'   (AES256-CFB generic)
         Master key ID           '9999999932323232'   (WalletEntry object)


   Anything in all capitals letters are sentinel values which mean: 
   "the calling code should recognize this sentinel value and provide 
   the specified data"


   Master Private Key in wallet will use:
             ArmoryCryptInfo( '11112222aaaabbbb',  
                              'ccccdddd88889999', 
                              'PASSPHRASEPLEASE', 
                              '<SerializedIV>')

   Private keys encrypted with master private key, use:
             ArmoryCryptInfo( '0000000000000000',  
                              'ccccdddd88889999',   
                              '9999999932323232',  
                              'PUBLICKEYHASH160')
   (Note no KDF:  because we use a KDF to protect master key... once
   the master key is unlocked, we just use the master key w/o KDF for
   the individual private keys) 


   Bare private key encryption w/o master key (use KDF & password):
             ArmoryCryptInfo( '11112222aaaabbbb',   
                              'ccccdddd88889999',   
                              'PASSPHRASEPLEASE',  
                              'PUBLICKEYHASH160')
   
   Encrypt P2SH scripts, labels, and meta-data in insecure backup file:
             ArmoryCryptInfo( '0000000000000000',  
                              'ccccdddd88889999',  
                              'PARENTCHAINCODE' ,  
                              '<SerializedIV>')

   Encrypt Public Keys & Addresses as WalletEntries:
             ArmoryCryptInfo( '11112222aaaabbbb',   
                              'ccccdddd88889999',   
                              'ROOTCHAINCODE256',  
                              '<SerializedIV>')

   No encryption 
             ArmoryCryptInfo( '0000000000000000',  
                              '0000000000000000',  
                              '0000000000000000',  
                              '0000000000000000')
   """




   ############################################################################
   def __init__(self, kdfAlgo=NULLSTR8, \
                      encrAlgo=NULLSTR8, \
                      keysrc=NULLSTR8, \
                      ivsrc=NULLSTR8):

      if kdfAlgo==None:
         kdfAlgo = NULLSTR8

      # Now perform the encryption using the encryption key
      if (not kdfAlgo==NULLSTR8) and (not KdfObject.kdfIsRegistered(kdfAlgo)):
         LOGERROR('Unrecognized KDF ID: %s', binary_to_hex(kdfAlgo))
         raise UnrecognizedCrypto

      # Now perform the encryption using the encryption key
      if not (encrAlgo==NULLSTR8) and (not encrAlgo in KNOWN_CRYPTO):
         LOGERROR('Unrecognized encryption algorithm: %s', encrAlgo)
         raise UnrecognizedCrypto

      self.kdfObjID     = kdfAlgo
      self.encryptAlgo  = encrAlgo
      self.keySource    = keysrc
      self.ivSource     = ivsrc
      self.extraData    = ''  # for forwards compatibility


   ############################################################################
   def noEncryption(self):
      return (self.kdfObjID==NULLSTR8 and \
              self.encryptAlgo==NULLSTR8 and \
              self.keySource==NULLSTR8 and \
              self.ivSource==NULLSTR8)

   #############################################################################
   def useEncryption(self):
      return (not self.encryptInfo.noEncryption())

   ############################################################################
   def useKeyDerivFunc(self):
      return (not self.kdf==NULLSTR8)

   ############################################################################
   def copy(self):
      return ArmoryCryptInfo().unserialize(self.serialize())

   ############################################################################
   def hasStoredIV(self):
      if self.ivSource==NULLSTR8:
         LOGWARNING('hasStoredIV() called on object with ID_ZERO.  All ')
         LOGWARNING('encryption objects should have a stored IV, or sentinel')
         return False

      # A non-zero ivSource is "stored" if it's not one of the sentinel values
      return (self.getEncryptIV()[0] == CRYPT_IV_SRC.STOREDIV)


   ############################################################################
   def setIV(self, newIV):
      if not self.ivSource==NULLSTR8:
         LOGWARNING('Setting IV on einfo object with non-zero IV')
      
      if not isinstance(newIV, str):
         newIV = newIV.toBinStr()

      if len(newIV)>8:
         LOGWARNING('Supplied IV is not 8 bytes. Truncating.')
      elif len(newIV)<8:
         LOGERROR('Supplied IV is less than 8 bytes.  Aborting')
         raise BadInputError

      self.ivSource = newIV

   ############################################################################
   def getEncryptKeySrc(self):
      if self.keySource=='PARCHAIN':
         return (CRYPT_KEY_SRC.PARCHAIN, '')
      elif self.keySource=='PASSWORD':
         return (CRYPT_KEY_SRC.PASSWORD, '')
      else:
         return (CRYPT_KEY_SRC.EKEYOBJ, self.keySource)



   ############################################################################
   def getBlockSize(self):
      if not KNOWN_CRYPTO.has_key(self.encryptAlgo):
         raise EncryptionError, 'Unknown crypto blocksize: %s' % self.encryptAlgo
      else:
         return KNOWN_CRYPTO[self.encryptAlgo]['blocksize']


   ############################################################################
   def getKeySize(self):
      # This is the keysize expected for this *ArmoryCryptInfo* object, not the
      # encryptAlgo of it.  In other words, this is to let us know the expected
      # size of the input -- if this ArmoryCryptInfo uses a KDF, there is no 
      # expected size.  Only if the no-KDF but does have encryptAlgo, then we
      # return the key size of that algo.
      if self.useKeyDerivFunc() or self.encryptAlgo:
         return 0
      elif(self.encryptAlgo.startswith('AE256'):
         return 32
      else:
         raise EncryptionError, 'Unknown encryption keysize'


   ############################################################################
   def getEncryptIVSrc(self):
      if self.ivSource=='PUBKEY20':
         return (CRYPT_IV_SRC.PUBKEY20, '')
      else:
         return (CRYPT_IV_SRC.STOREDIV, self.ivSource)

      

   ############################################################################
   def serialize(self):
      bp = BinaryPacker()
      bp.put(BINARY_CHUNK,  self.kdfObjID,      widthBytes=8)
      bp.put(BINARY_CHUNK,  self.encryptAlgo,   widthBytes=8)
      bp.put(BINARY_CHUNK,  self.keySource,     widthBytes=8)
      bp.put(BINARY_CHUNK,  self.ivSource,      widthBytes=8)
      bp.put(VAR_STR,       self.extraData)


   ############################################################################
   def unserialize(self, theStr):
      bu = makeBinaryUnpacker(toUnpack)
      self.kdfObjID    = bu.get(BINARY_CHUNK, 8)
      self.encryptAlgo = bu.get(BINARY_CHUNK, 8)
      self.keySource   = bu.get(BINARY_CHUNK, 8)
      self.ivSource    = bu.get(BINARY_CHUNK, 8)
      self.extraData   = bu.get(VAR_STR)
      return self
       
   ############################################################################
   def copy(self):
      return ArmoryCryptInfo().unserialize(self.serialize())

   ############################################################################
   @VerifyArgTypes(plaintext=SecureBinaryData, \
                   keyData=SecureBinaryData,  \
                   ivData=SecureBinaryData)
   def encrypt(self, plaintext, ekeyObj=None, keyData=None, ivData=None):
      """
      Ways this function is used:

         -- We are encrypting the data with a KDF & passphrase only:
               ekeyObj == None
               keyData is the passphrase
               keyData will pass through the KDF
               ivData contains the IV to use for encryption of this object

         -- We are encrypting with a raw AES256 key
               ekeyObj == None
               keyData is the raw AES key
               KDF is ignored
               ivData contains the IV to use for encryption of this object

         -- We are encrypting using a master key 
               ekeyObj == MasterKeyObj
               Decrypt MasterKey using keyData and the MasterKey's stored IV
               Overwrite keyData arg with the decrypted master key, carry on
               ivData contains the IV to use for encryption of this object

      Here, "keydata" may actually be a passphrase entered by the user, which 
      will get stretched into the actual encryption key.  If there is no KDF,
      then keydata is simply the encryption key, provided by the calling func
      while likely checked the keySource and ivSource and fetched appropriate 
      data for encryption/decryption.

      If ekeyObj is supplied, then we are saying that the given ekey is 
      required for encryption/decryption and the keydata is provided as 
      the passphrase to unlock the ekey.  

      In the case that ivData is supplied, it is assumed it is the IV for
      *this data*, not for the ekeyObj -- because ekey objects usually carry 
      their own IV with them.  If you are doing something much more general 
      or non-standard, this method may have to be adjusted to accommodate 
      more complicated schemes.

      We need to fail if plaintext is not padded to the blocksize of the
      cipher.  The reason is that this function should only pass out encrypted
      data that exactly corresponds to the input, not some variant of it.  
      If the data needs padding, the calling method can ask the CryptInfo
      object for the cipher blocksize, and pad it before passing in (and also
      take note somewhere of what the original datasize was).
      """

      if not (isinstance(plaintext, SecureBinaryData) and \
              isinstance(keyData,   SecureBinaryData) and \
              isinstance(ivData,    SecureBinaryData)):
         raise TypeError('Not all input strings are SecureBinaryData objects') 


      weCreatedKeyData = False

      try:
         # Verify that the plaintext data has correct padding
         plaintext = SecureBinaryData(plaintext)
         if not (plaintext.getSize() % self.getBlockSize() == 0):
            LOGERROR('Plaintext has wrong length: %d bytes', plaintext.getSize())
            LOGERROR('Length expected to be padded to %d bytes', self.getBlockSize())
            raise EncryptionError('Cannot encrypt non-multiple of crypto-blocksize')

         # IV data might actually be part of this object, not supplied
         if not self.hasStoredIV():
            if not ivData:
               LOGERROR('Cannot encrypt without initialization vector.')
               raise InitVectError 
            ivData = SecureBinaryData(ivData)
         elif not ivData:
            ivData = self.ivSource.copy()
         else:
            LOGERROR('ArmoryCryptInfo has stored IV and was also supplied one!')
            LOGERROR('Do not want to risk encrypting with wrong IV ... bailing')
            raise InitVectError 
   
         # All IV data is 8 bytes, though we need 16-byte IVs.  The IVs only need
         # a small amount of entropy in them -- 8 bytes is enough.  
         ivData.padDataMod(self.getBlockSize())
   
   
         # If we are using a master encryption key, then we create a modified
         # copy of self, using the unlocked ekey as the key data.  
         if ekeyObj is None:
            keysrc = self.getEncryptKeySrc()[0]
            if keysrc == CRYPT_KEY_SRC.EKEYOBJ:
               LOGERROR('EncryptionKey object required but not supplied')
               raise EncryptionError
         else:
            # We have supplied a master key to help encrypt this object
            if self.useKeyDerivFunc():
               LOGERROR('Master key encryption should never use a KDF')
               raise EncryptionError
   
            # If supplied master key is correct, its ID should match stored value
            if not ekeyObj.getEncryptionKeyID() == self.keySource:
               LOGERROR('Supplied ekeyObj does not match keySource, in encrypt')
               raise EncryptionError
   
            # Make sure master key is unlocked -- use keyData arg if locked
            if ekeyObj.isLocked():         
               if keyData==None:
                  LOGERROR('Supplied locked ekeyObj without passphrase')
                  raise EncryptionError
   
               # Use the supplied keydata to unlock the *MASTER KEY*
               # Note "unlock" will call the ekeyObj.einfo.decrypt
               if not ekeyObj.unlock(keyData):
                  LOGERROR('Supplied locked ekeyObj incorrect passphrase')
                  raise EncryptionError
   
            # Now replace the keyData arg with the decrypted master key 
            keyData = ekeyObj.masterKeyPlain.copy()
            ekeyObj.lock()
            weCreatedKeyData = True
            
   
   
         # Apply KDF if it's requested
         if self.useKeyDerivFunc(): 
            if not KdfObject.kdfIsRegistered(self.kdfObjID):
               LOGERROR('KDF is not registered: %s', binary_to_hex(self.kdfObjID))
               raise EncryptionError
            keyData = KdfObject.REGISTERED_KDFS[self.kdfObjID].execKDF(keyData)
   
         # Now perform the encryption using the encryption key
         if self.encryptAlgo=='AE256CFB':
            return CryptoAES().EncryptCFB(plaintext, keyData, ivData)
         elif self.encryptAlgo=='AE256CBC':
            return CryptoAES().EncryptCBC(plaintext, keyData, ivData)
         else:
            LOGERROR('Unrecognized encryption algorithm: %s', self.encryptAlgo)
            raise EncryptionError
            
      finally:
         # We only destroy stuff we created.  We don't destroy input args,
         # as the calling function should be responsible for those.
         if weCreatedKeyData:
            keyData.destroy()



   ############################################################################
   def decrypt(self, ciphertext, ekeyObj=None, keyData=None, ivData=None):
      """
      See comments for encrypt function -- this function works the same way
      """


      # If we are using a master encryption key, then we create a modified
      # copy of self, using the unlocked ekey as the key data.  
      if not ekeyObj==None:
         einfo = self.copy()
         if not ekeyObj.getEncryptionKeyID() == self.keySource:
            LOGERROR('Supplied ekeyObj does not match keySource, in encrypt')
            raise EncryptionError

         if ekeyObj.isLocked():         
            if keyData==None:
               LOGERROR('Supplied locked ekeyObj without passphrase')
               raise EncryptionError

            if not ekeyObj.unlock(keyData):
               LOGERROR('Supplied locked ekeyObj incorrect passphrase')
               raise EncryptionError

         masterKey = ekeyObj.masterKeyPlain.copy()
         einfo.encryptAlgo = ekeyObj.ekeyType
         # einfo is now a non-master-key-required ArmoryCryptInfo object.
         # The key data required is just the plaintext of the master key.
         return einfo.decrypt(ciphertext, keyData=masterKey, ivData=ivData)
      else:
         keysrc = self.getEncryptKeySrc()[0]
         if keysrc == CRYPT_KEY_SRC.EKEYOBJ:
            LOGERROR('EncryptionKey object required but not supplied')
            raise EncryptionError


      # Make sure all the data is in SBD form -- will also be easier to destroy
      ciphertext = SecureBinaryData(ciphertext)
      if not (ciphertext.getSize() % self.getBlockSize() == 0):
         LOGERROR('Ciphertext has wrong length: %d bytes', ciphertext.getSize())
         LOGERROR('Length expected to be padded to %d bytes', self.getBlockSize())
         raise EncryptionError, 'Cannot decrypt non-multiple of blocksize'

      # IV data might actually be part of this object, not supplied
      if not self.hasStoredIV():
         if not ivData:
            LOGERROR('Cannot decrypt without initialization vector.')
            return
         ivData = SecureBinaryData(ivData)
      elif not ivData:
         ivData = self.ivSource.copy()
      else:
         # Don't need to bail because this failing does not cause irreversible 
         # damage like if we encrypt with one IV and store a different one.
         LOGERROR('ArmoryCryptInfo has stored IV and was also supplied one!')
         LOGERROR('Using stored IV to attempt to decrypt')

      # All IV data is 8 bytes, though we need 16-byte IVs.  The IVs only need
      # a small amount of entropy in them -- 8 bytes is enough.  
      ivData.padDataMod(self.getBlockSize())

      # Apply KDf if it's requested
      if self.useKeyDerivFunc(): 
         if not self.kdfObjID in KdfObject.REGISTERED_KDFS:
            LOGERROR('KDF is not registered: %s', binary_to_hex(self.kdfObjID))
            plain = SecureBinaryData(0)
         keyData = REGISTERED_KDFS[self.kdfObjID].execKDF(keyData)

      # Now perform the decryption using the key
      if self.encryptAlgo=='AE256CFB':
         plain = CryptoAES().DecryptCFB(ciphertext, keyData, ivData)
      elif self.encryptAlgo=='AE256CBC':
         plain = CryptoAES().DecryptCBC(ciphertext, keyData, ivData)
      else:
         LOGERROR('Unrecognized encryption algorithm: %s', self.encryptAlgo)
         plain = SecureBinaryData(0)
         
      ciphertext.destroy()
      keyData.destroy()
      ivData.destroy()
      return plain





#############################################################################
class KdfObject(object):
   """
   Note that there is only one real KDF *algorithm* here, but each wallet
   has system-specific parameters required to execute the KDF (32-byte salt
   and memory required).  Therefore, there may be multiple KdfObjects even
   though they are all using the same underlying algorithm.

   ROMix-Over-2 is based on Colin Percival's ROMix algorithm which was the
   provably-memory-hard key stretching algorithm that preceded "scrypt."  
   ROMix was chosen because of its simplicity, despite its lack of flexibility
   in choosing memory-vs-speed tradeoff.  It is "-over-2" because the number
   of LUT operations is cut in half relative to described ROMix algorithm,
   in order to allow larger memory usage on slower systems.
   """
   KDF_ALGORITHMS = { 'identity': [], 
                      'romixov2': ['memReqd','numIter','salt'],
                      'scrypt__': ['n','r','i'] }
   REGISTERED_KDFS = { }

   #############################################################################
   def __init__(self, kdfName=None, **params):

      if kdfName==None:
         self.kdfName = ''
         self.kdf = None
         def errorkdf(x):
            LOGEXCEPT('KDF not initialized!')
            return SecureBinaryData(0)
         self.execKDF = errorkdf
         return
         
      if not kdfName.lower() in self.KDF_ALGORITHMS:
         LOGERROR('Attempted to create unknown KDF object:  name=%s', kdfName)
         return

      reqdArgs = self.KDF_ALGORITHMS[kdfName.lower()]
      for arg in reqdArgs:
         if not arg in params:
            LOGERROR('KDF name=%s:   not enough input arguments', kdfName)
            LOGERROR('Required args: %s', ''.join(reqdArgs))
            return
            

      # Right now there is only one algo.  You can add your own via "KDF_ALGORITHMS" 
      # and then updating this method to create a callable KDF object
      if kdfName.lower()=='identity':
         self.execKDF = lambda x: SecureBinaryData(x)
      if kdfName.lower()=='romixov2':

         memReqd = params['memReqd']
         numIter = params['numIter']
         salt    = params['salt'   ]

         # Make sure that non-SBD input is converted to SBD
         saltSBD = SecureBinaryData(salt)

         if memReqd>2**31:
            LOGERROR('Invalid memory for KDF.  Must be 2GB or less.')
            return
         

         if saltSBD.getSize()==0:
            LOGERROR('Zero-length salt supplied with KDF. If creating new, use ')
            LOGERROR('     salt=SecureBinaryData().GenerateRandom(16)')
            return
            
         self.kdfName = 'ROMixOv2'
         self.memReqd = memReqd
         self.numIter = numIter
         self.salt    = saltSBD
         self.kdf = KdfRomix(self.memReqd, self.numIter, self.salt) 
         self.execKDF = lambda pwd: self.kdf.DeriveKey( SecureBinaryData(pwd) )

      else:
         LOGERROR('Unrecognized KDF name')
      

   #############################################################################
   def execKDF(self, passphrase):
      # This method is normally assigned in the setKDF function.  This is here
      # to throw an error in case it isn't
      LOGERROR('KDF.execKDF() was never overwritten.  No KDF to execute')
      raise EncryptionError

   #############################################################################
   def getKdfID(self):
      return computeChecksum(self.serialize(), 8)
      
   ############################################################################
   # STATIC METHOD (no self)
   def RegisterKDF(kdfObj):
      LOGINFO('Registering KDF object: %s', binary_to_hex(kdfObj.getKdfID()))
      KdfObject.REGISTERED_KDFS[kdfObj.getKdfID()] = kdfObj

   ############################################################################
   # STATIC METHOD (no self)
   def kdfIsRegistered(kdfObjID):
      return KdfObject.REGISTERED_KDFS.has_key(kdfObjID)

   ############################################################################
   # STATIC METHOD (no self)
   def getRegisteredKDF(kdfID):
      if not KdfObject.kdfIsRegistered(kdfID):
         LOGERROR('KDF is not registered: %s', binary_to_hex(kdfID))
         raise UnrecognizedCrypto
      return KdfObject.REGISTERED_KDFS[kdfID] 

   #############################################################################
   def serialize(self):
      bp = BinaryPacker()
      if self.kdfName.lower()=='romixov2':
         bp.put(BINARY_CHUNK, self.kdfname,           widthBytes= 8)
         bp.put(BINARY_CHUNK, 'SHA512',               widthBytes= 8)
         bp.put(UINT32,       self.memReqd)          #widthBytes= 4
         bp.put(UINT32,       self.numIter)          #widthBytes= 4
         bp.put(BINARY_CHUNK, self.salt.toBinStr(),   widthBytes=32)
      elif self.kdfName.lower()=='identity':
         bp.put(BINARY_CHUNK, 'Identity',             widthBytes= 8)
      return bp.getBinaryString()
      
   #############################################################################
   def unserialize(self, toUnpack):
      bu = makeBinaryUnpacker(toUnpack)
      kdfName = bu.get(BINARY_CHUNK, 8)
      if not kdfName.lower() in self.KDF_ALGORITHMS:
         LOGERROR('Unknown KDF in unserialize:  %s', kdfName)
         return None
     
      # Start the KDF-specific processing
      if kdfName.lower()=='identity':
         self.__init__('Identity')
      elif kdfName.lower()=='romixov2':
         useHash = bu.get(BINARY_CHUNK,  8)
         if not useHash.lower().startswith('sha512'):
            LOGERROR('No pre-programmed KDFs use hash function: %s', useHash)
            return
         mem = bu.get(UINT32)
         nIter = bu.get(UINT32)
         slt = bu.get(BINARY_CHUNK, 32)
         self.__init__(kdfName, memReqd=mem, numIter=nIter, salt=slt)

      return self



   #############################################################################
   def createNewKDF(self, kdfName, targSec=0.25, maxMem=32*1024*1024, \
                                                           doRegisterKDF=True):
      
      LOGINFO("Creating new KDF object")

      if not (0 <= targSec <= 20):
         LOGERROR('Must use positive time <= 20 sec.  Use 0 for min settings')
         return None

      if not (32*1024 <= maxMem <= 2**31):
         LOGERROR('Must use maximum memory between 32 kB and 2048 MB')
         return None

      if not kdfName.lower() in self.KDF_ALGORITHMS:
         LOGERROR('Unknown KDF name in createNewKDF:  %s', kdfName)
         return None

      if kdfName.lower()=='identity':
         self.__init__('Identity')
         LOGINFO('Created identity identity KDF')
      elif kdfName.lower()=='romixov2':
         kdf = KdfRomix()
         kdf.computeKdfParams(targetSec, maxMem)
   
         mem   = kdf.getMemoryReqtBytes()
         nIter = kdf.getNumIterations()
         slt   = kdf.getSalt().toBinStr()
         self.__init__('ROMixOv2', memReqd=mem, numIter=nIter, salt=slt)

         LOGINFO('Created new KDF with the following parameters:')
         LOGINFO('\tAlgorithm: %s', kdfName)
         LOGINFO('\t%d kB',  (int(mem)/1024))
         LOGINFO('\t%d iterations', nIter)
         LOGINFO('\tSalt: %s', self.kdf.getSalt().toHexStr())

      if doRegisterKDF:
         KdfObject.RegisterKDF(self)

      return self



#############################################################################
#############################################################################
class EncryptionKey(object):

   #############################################################################
   def __init__(self, keytype=None, keyid=None, einfo=None, ekey=None, etest=None, ptest=None):
      self.ekeyType           = keytype if keytype else SecureBinaryData(0)
      self.ekeyID             = keyid   if keyid   else SecureBinaryData(0)
      self.masterKeyEncrypted = SecureBinaryData(ekey)  if ekey  else SecureBinaryData(0)
      self.testStringEncr     = SecureBinaryData(etest) if etest else SecureBinaryData(0)
      self.testStringPlain    = SecureBinaryData(ptest) if ptest else SecureBinaryData(0)

      self.encryptInfo = ArmoryCryptInfo(None)
      if einfo:
         if isinstance(einfo, str):
            self.encryptInfo.unserialize(einfo)
         elif isinstance(einfo, ArmoryCryptInfo):
            self.encryptInfo = einfo.copy()
         else:
            LOGERROR('Unrecognized einfo object in EncryptionKey')
            raise UnrecognizedCrypto

      # We may cache the decrypted key      
      self.masterKeyPlain      = SecureBinaryData(0)
      self.relockAtTime        = 0
      self.lockTimeout         = 10


   #############################################################################
   def EncryptionKeyToID(self, rawkey, ekeyalgo):
      # A static method that computes an 8-byte ID for any raw string
      # Essentially a hash of the 32-byte key and its type (i.e. 'AE256CFB')
      rawkey = SecureBinaryData(rawkey)
      hmac = HDWalletCrypto().HMAC_SHA512(rawkey, ekeyalgo)
      rawkey.destroy()
      return hmac.toBinStr()[:8]


   ############################################################################
   def getBlockSize(self):
      if not KNOWN_CRYPTO.has_key(self.ekeyType):
         raise EncryptionError, 'Unknown crypto blocksize: %s' % self.ekeyType
      else:
         return KNOWN_CRYPTO[self.ekeyType]['blocksize']
   
   #############################################################################
   def getEncryptionKeyID(self):
      if self.ekeyID==None:
         # Needs to be computed
         if self.isLocked():
            LOGERROR('No stored ekey ID, and ekey is locked so cannot compute')
            raise EncryptionError
         self.ekeyID = EncryptionKey().EncryptionKeyToID(self.masterKeyPlain, \
                                                         self.ekeyType)
      return self.ekeyID

   #############################################################################
   def verifyPassphrase(self, passphrase):
      passphrase = SecureBinaryData(passphrase)
      tempKey = self.encryptInfo.decrypt(self.masterKeyEncrypted, passphrase)
      out = (self.EncryptionKeyToID(tempKey)==self.ekeyID)
      passphrase.destroy()
      tempKey.destroy()
      return out


   #############################################################################
   def unlock(self, passphrase):
      LOGDEBUG('Unlocking encryption key %s', self.ekeyID)
      try:
         passphrase = SecureBinaryData(passphrase)
         self.masterKeyPlain = \
                  self.encryptInfo.decrypt(self.masterKeyEncrypted, passphrase)
         if not self.EncryptionKeyToID(self.masterKeyPlain)==self.ekeyID:
            LOGERROR('Wrong passphrase passed to EKEY unlock function.')
            self.masterKeyPlain.destroy()
            return False
         self.relockAtTime = RightNow() + self.lockTimeout
         return True
      finally:
         passphrase.destroy()



   #############################################################################
   def lock(self, passphrase=None):
      LOGDEBUG('Locking encryption key %s', self.ekeyID)
      try:
         if self.masterKeyEncrypted.getSize()==0:
            if passphrase==None:
               LOGERROR('No encrypted master key available and no passphrase for lock()')
               LOGERROR('Deleting it anyway.')
               return False
            else:
               passphrase = SecureBinaryData(passphrase)
               self.masterKeyEncrypted = \
                        self.encryptInfo.encrypt(self.masterKeyPlain, passphrase)
               passphrase.destroy()
               return True
      finally:
         self.masterKeyPlain.destroy()


   #############################################################################
   def setLockTimeout(self, newTimeout): 
      self.lockTimeout = newTimeout

   #############################################################################
   def checkLockTimeout(self): 
      """ timeout=0 means never expires """
      if self.lockTimeout<=0:
         return
         
      if RightNow() > self.relockAtTime:
         self.lock()


   #############################################################################
   def isLocked(self):
      return (self.masterKeyPlain.getSize() == 0)


   #############################################################################
   def serialize(self):
      bp = BinaryPacker()
      bp.put(BINARY_CHUNK, self.ekeyType,                  widthBytes= 8)
      bp.put(BINARY_CHUNK, self.ekeyID,                    widthBytes= 8)
      bp.put(BINARY_CHUNK, self.encryptInfo.serialize(),   widthBytes=32)
      bp.put(BINARY_CHUNK, self.masterKeyEncrypted,        widthBytes=32)
      bp.put(BINARY_CHUNK, self.testStringEncr,            widthBytes=32)
      bp.put(BINARY_CHUNK, self.testStringPlain,           widthBytes=32)
      return bp.getBinaryString()


   #############################################################################
   def unserialize(self, strData):
      bu = makeBinaryUnpacker(strData)
      ekeyType = bu.get(BINARY_CHUNK,  8)
      ekeyID   = bu.get(BINARY_CHUNK,  8)
      einfoStr = bu.get(BINARY_CHUNK, 32)
      emaster  = bu.get(BINARY_CHUNK, 32)
      eteststr = bu.get(BINARY_CHUNK, 32)
      pteststr = bu.get(BINARY_CHUNK, 32)
      self.__init__(ekeyID, ekeyType, einfoStr, emaster, eteststr, pteststr)
      return self


   #############################################################################
   def CreateNewMasterKey(self, encryptKeyKDF, encryptKeyAlgo, sbdPasswd,
                                withTestString=True, masterKeyType=None):
      """
      This method assumes you already have a KDF you want to use and is 
      referenced by the first arg.  If not, please create the KDF and
      add it to the wallet first (and register it with KdfObject before 
      using this method.

      Generally, ArmoryCryptInfo objects can have a null KDF, but not for 
      master encryption key objects (though just about anything is possible
      with the ArmoryCryptInfo types)
      """

      LOGINFO('Generating new master key')

      # Check for the existence of the specified KDF      
      if isinstance(encryptKeyKDF, KdfObject):
         kdfID = encryptKeyKDF.getKdfID()
         if not KdfObject.kdfIsRegistered(kdfID):
            LOGERROR('Somehow we got a KDF object that is not registered')
            LOGERROR('Not going to use it, because if it is not registered, ')
            LOGERROR('it also may not be part of the wallet, yet.')
            raise UnrecognizedCrypto
      elif isinstance(encryptKeyKDF, str):
         kdfID = encryptKeyKDF[:]
         if not KdfObject.kdfIsRegistered(kdfID):
            LOGERROR('Key Deriv Func is not registered.  Cannot create new ')
            LOGERROR('master key without using a known KDF.  Can create a ')
            LOGERROR('new KDF via ')
            LOGERROR('KdfObject().createNewKDF("ROMixOv2", targSec=X, maxMem=Y)')
            raise UnrecognizedCrypto
      else:
         LOGERROR('Bad argument type for "encryptKeyKDF"')
         raise BadInputError


      # Check that we recognize the encryption algorithm
      # This is the algorithm used to encrypt the master key itself
      if not encryptKeyAlgo in KNOWN_CRYPTO:
         LOGERROR('Unrecognized crypto algorithm: %s', encryptKeyAlgo)
         raise UnrecognizedCrypto

      # The masterKeyType is the encryption algorithm that is intended to
      # be used with this key (once it is decrypted to unlock the wallet).
      # This will usually be the same as the encryptKeyAlgo, but I guess 
      # it doesn't have to be
      if masterKeyType==None:
         self.ekeyType = encryptKeyAlgo
      else:
         if not masterKeyType in KNOWN_CRYPTO:
            LOGERROR('Unrecognized crypto algorithm: %s', masterKeyType)
            raise UnrecognizedCrypto
         self.ekeyType = masterKeyType
         
      # Master encryption keys will always be stored with IV
      storedIV = SecureBinaryData().GenerateRandom(8)
      self.encryptInfo = ArmoryCryptInfo(kdfID, encryptKeyAlgo, \
                                         'PASSWORD', storedIV)

      # Create the master key...
      self.masterKeyPlain = SecureBinaryData().GenerateRandom(32)
      self.ekeyID = self.EncryptionKeyToID(self.masterKeyPlain)
      self.masterKeyEncrypted = self.encryptInfo.encrypt(self.masterKeyPlain, \
                                                         sbdPasswd)

      if not withTestString:
         self.testStringPlain = '\x00'*32
         self.testStringEncr  = '\x00'*32
      else:
         rand16 = SecureBinaryData().GenerateRandom(16)
         self.testStringPlain = SecureBinaryData('ARMORYENCRYPTION') + rand16
         testStrIV = self.ekeyID*2  
         if encryptKeyAlgo=='AE256CBC': 
            self.testStringEncr = CryptoAES().EncryptCBC(self.testStringPlain, \
                                                         self.masterKeyPlain, \
                                                         testStrIV)
         elif encryptKeyAlgo=='AE256CFB': 
            self.testStringEncr = CryptoAES().EncryptCFB(self.testStringPlain, \
                                                         self.masterKeyPlain, \
                                                         testStrIV)
         else:
            LOGERROR('Unrecognized encryption algorithm')
      
      self.masterKeyPlain.destroy()

      LOGINFO('Finished creating new master key:')
      LOGINFO('\tKDF:     %s', binary_to_hex(kdfID))
      LOGINFO('\tCrypto:  %s', encryptKeyAlgo)
      LOGINFO('\tTestStr: %s', binary_to_hex(self.testStringPlain[16:]))


   #############################################################################
   def createKeyRecoveryChallenge(self, useremail, userhints):
      """
      If the encryption key was created with a test string, this function will
      return all the information needed for someone to start brute-forcing it.
      This is so that there is *SOME* recourse for users that were dumb enough
      to not make any backups, and then forget their passphrase.  The guesses
      still have to go through the KDf, but this recovery challenge can be 
      distributed to hired computing resources without actually giving up their
      wallet -- i.e. the people racing to help the user the unlock their wallet 
      (and presumably get some portion/bounty), can know that they've found the
      answer without actually getting access to the wallet.

      Without the test strings, the user has to distribute the entire wallet
      and hope that the person that finds the passphrase will be nice enough
      to give them back any of the funds.  There's nothing stopping them
      from just taking it.

      Additionally, the brute-forcer can prove that they found the password
      without actually revealing it.  This is because when they've found the
      key, they will gain access to the [secret] second half of the test
      string, which can be used as a shared secret for an HMAC, when they
      contact the user to tell them they found the key.

      I posted about this on Bitcointalk.org... let me find it...
      """

      # If the plain string is all zero-bytes, then this key was created 
      # without the test strings
      if self.testStringPlain.toBinStr() == '\x00'*32:
         return ''

      kdfid  = self.encryptInfo.kdfObjID
      kdfObj = KdfObject.getRegisteredKDF(kdfid)

      fmtChallenge = []
      fmtChallenge.append( '-'*80 )
      fmtChallenge.append( 'Armory Master Key Recovery Challenge' )
      fmtChallenge.append( '-'*80 )
      fmtChallenge.append( '' )
      fmtChallenge.append( 'The master key is encrypted in the following way:' )
      if kdfObj.kdfName.lower()=='romixov2' :
         fmtChallenge.append( '   Encryption:    ' + self.encryptInfo.encryptAlgo)
         fmtChallenge.append( '   KDF Algorithm: ' + kdfObj.kdfName )
         fmtChallenge.append( '   KDF Mem Used:  ' + kdfObj.memReqd )
         fmtChallenge.append( '   KDF NumIter:   ' + kdfObj.numIter )
         fmtChallenge.append( '' )
         fmtChallenge.append( '   KDF Salt:      ' + kdfObj.salt.toHexStr()[:32] )
         fmtChallenge.append( '                  ' + kdfObj.salt.toHexStr()[32:] )
         fmtChallenge.append( '' )
         fmtChallenge.append( '   Encryption:    ' )
         fmtChallenge.append( '   Encrypted Key: ' + kdfObj.masterKeyEncrypted.toHexStr()[:32])
         fmtChallenge.append( '                  ' + kdfObj.masterKeyEncrypted.toHexStr()[32:])
      fmtChallenge.append( '' )
      fmtChallenge.append( 'The test string is 32 bytes, encrypted with the above key:' )
      fmtChallenge.append( '   Encrypted Str ' + self.testStringEncr.toHexStr()[:32])
      fmtChallenge.append( '                 ' + self.testStringEncr.toHexStr()[32:])
      fmtChallenge.append( '' )
      fmtChallenge.append( 'The decrypted test string starts with the following:')
      fmtChallenge.append( '   First16 (ASCII): ARMORYENCRYPTION')
      fmtChallenge.append( '   First16 (HEX):   41524d4f5259454e4352595054494f4e')
      fmtChallenge.append( '' )
      fmtChallenge.append( 'Once you have found the correct passphrase, you can ')
      fmtChallenge.append( 'use the second 16 bytes as proof that you have succeeded. ')
      fmtChallenge.append( 'Use the entire decrypted string as the secret key to ')
      fmtChallenge.append( 'send a message authentication code to the user with ')
      fmtChallenge.append( 'your email address (or any other identifying information ')
      fmtChallenge.append( 'you wish to use.')
      fmtChallenge.append( '' )
      fmtChallenge.append( 'The message authentication code is computed like this: ')
      fmtChallenge.append( '   mac = toHex(HMAC_SHA512(decrypted32, emailaddress)[:32])')
      fmtChallenge.append( '' )
      fmtChallenge.append( '-'*100 )
      fmtChallenge.append( 'The following information is supplied by the user to ')
      fmtChallenge.append( 'help you find the passphrase and submit your proof: ')
      fmtChallenge.append( '' )
      fmtChallenge.append( '   User email: ' + useremail )
      fmtChallenge.append( '   User hints: ')
      for i in range(0,len(userhints)+50, 50):
         fmtChallenge.append( '      ' + userhints[50*i:50*(i+1)])
      fmtChallenge.append( '' )
      fmtChallenge.append( '-'*100 )
      return '\n'.join(fmtChallenge)
      

   #############################################################################
   def testKeyRecoveryMAC(self, userstr, responseMacHex):
      LOGINFO('Testing key recovery MAC:')

      LOGINFO('   User Info :     %s', userstr)
      userstr = SecureBinaryData(userstr)
      hmac = HDWalletCrypto().HMAC_SHA512(self.testStringPlain, userstr)

      LOGINFO('   MAC (given):    %s', responseMacHex)
      LOGINFO('   MAC (correct):  %s', hmac.toHexStr()[:64])
      return (hmac.toHexStr()[:64]==responseMacHex)
   

         
#############################################################################
#############################################################################
class MultiPwdEncryptionKey(object):
   """
   Instead of storing a single master encryption key which is encrypted
   with a password, we're going to have an M-of-N split of the master
   encryption key, each on encrypted with a different password.  So instead
   of :

      ekeyInfo | encryptedMasterKey

   we will have:

      ekeyInfoA | encryptedMasterFragA | ekeyInfoB | encryptedMasterFragB | ...

   We intentionally do not have a way to verify if an individual password
   is correct without having a quorum of correct passwords.  This makes
   sure that master key is effectively encrypted with the entropy of 
   M passwords, instead of M keys each encrypted with the entropy of one
   password (reduced ever so slightly if M != N)
   """

   #############################################################################
   def __init__(self, keytype=None, keyid=None, efragList=None):
      self.ekeyType           = keytype if keytype else SecureBinaryData(0)
      self.ekeyID             = keyid   if keyid   else SecureBinaryData(0)

      if efragList and not isinstance(efragList, (list,tuple)):
         LOGERROR('Need to provide list of einfo & SBD objects for frag list')
         raise BadInputError
      
      if efragList:
         self.efrags = [[i,SecureBinaryData(f)] for i,f in efragList]

      # If the object is unlocked, we'll store a the plain master key here
      self.masterKeyPlain      = SecureBinaryData(0)
      self.relockAtTime        = 0
      self.lockTimeout         = 10


   #############################################################################
   def EncryptionKeyToID(self, rawkey, ekeyalgo):
      # A static method that computes an 8-byte ID for any raw string
      # Essentially a hash of the 32-byte key and its type (i.e. 'AE256CFB')
      rawkey = SecureBinaryData(rawkey)
      hmac = HDWalletCrypto().HMAC_SHA512(rawkey, ekeyalgo)
      rawkey.destroy()
      return hmac.toBinStr()[:8]


   ############################################################################
   def getBlockSize(self):
      if not KNOWN_CRYPTO.has_key(self.ekeyType):
         raise EncryptionError, 'Unknown crypto blocksize: %s' % self.ekeyType
      else:
         return KNOWN_CRYPTO[self.ekeyType]['blocksize']
   
   #############################################################################
   def getEncryptionKeyID(self):
      if self.ekeyID==None:
         # Needs to be computed
         if self.isLocked():
            LOGERROR('No stored ekey ID, and ekey is locked so cannot compute')
            raise EncryptionError
         self.ekeyID = EncryptionKey().EncryptionKeyToID(self.masterKeyPlain, \
                                                         self.ekeyType)
      return self.ekeyID

   #############################################################################
   def verifyPassphrase(self, passphrase):
      passphrase = SecureBinaryData(passphrase)
      tempKey = self.encryptInfo.decrypt(self.masterKeyEncrypted, passphrase)
      out = (self.EncryptionKeyToID(tempKey)==self.ekeyID)
      passphrase.destroy()
      tempKey.destroy()
      return out


   #############################################################################
   def unlock(self, passphrase):
      LOGDEBUG('Unlocking encryption key %s', self.ekeyID)
      try:
         passphrase = SecureBinaryData(passphrase)
         self.masterKeyPlain = \
                  self.encryptInfo.decrypt(self.masterKeyEncrypted, passphrase)
         if not self.EncryptionKeyToID(self.masterKeyPlain)==self.ekeyID:
            LOGERROR('Wrong passphrase passed to EKEY unlock function.')
            self.masterKeyPlain.destroy()
            return False
         self.relockAtTime = RightNow() + self.lockTimeout
         return True
      finally:
         passphrase.destroy()



   #############################################################################
   def lock(self, passphrase=None):
      LOGDEBUG('Locking encryption key %s', self.ekeyID)
      try:
         if self.masterKeyEncrypted.getSize()==0:
            if passphrase==None:
               LOGERROR('No encrypted master key available and no passphrase for lock()')
               LOGERROR('Deleting it anyway.')
               return False
            else:
               passphrase = SecureBinaryData(passphrase)
               self.masterKeyEncrypted = \
                        self.encryptInfo.encrypt(self.masterKeyPlain, passphrase)
               passphrase.destroy()
               return True
      finally:
         self.masterKeyPlain.destroy()


   #############################################################################
   def setLockTimeout(self, newTimeout): 
      self.lockTimeout = newTimeout

   #############################################################################
   def checkLockTimeout(self): 
      """ timeout=0 means never expires """
      if self.lockTimeout<=0:
         return
         
      if RightNow() > self.relockAtTime:
         self.lock()


   #############################################################################
   def isLocked(self):
      return (self.masterKeyPlain.getSize() == 0)


   #############################################################################
   def serialize(self):
      bp = BinaryPacker()
      bp.put(BINARY_CHUNK, self.ekeyType,                  widthBytes= 8)
      bp.put(BINARY_CHUNK, self.ekeyID,                    widthBytes= 8)
      bp.put(BINARY_CHUNK, self.encryptInfo.serialize(),   widthBytes=32)
      bp.put(BINARY_CHUNK, self.masterKeyEncrypted,        widthBytes=32)
      return bp.getBinaryString()


   #############################################################################
   def unserialize(self, strData):
      bu = makeBinaryUnpacker(strData)
      ekeyType = bu.get(BINARY_CHUNK,  8)
      ekeyID   = bu.get(BINARY_CHUNK,  8)
      einfoStr = bu.get(BINARY_CHUNK, 32)
      emaster  = bu.get(BINARY_CHUNK, 32)
      self.__init__(ekeyID, ekeyType, einfoStr, emaster, eteststr, pteststr)
      return self


   #############################################################################
   def CreateNewMultiPwdKey(self, encryptKeyKDF, encryptKeyAlgo, 
                                sbdPasswd, passwdType=(1,1),
                                withTestString=True, masterKeyType=None):
      """
      This method assumes you already have a KDF you want to use and is 
      referenced by the first arg.  If not, please create the KDF and
      add it to the wallet first (and register it with KdfObject before 
      using this method.

      Generally, ArmoryCryptInfo objects can have a null KDF, but not for 
      master encryption key objects (though just about anything is possible
      with the ArmoryCryptInfo types)
      """

      LOGINFO('Generating new master key')

      # Check for the existence of the specified KDF      
      if isinstance(encryptKeyKDF, KdfObject):
         kdfID = encryptKeyKDF.getKdfID()
         if not KdfObject.kdfIsRegistered(kdfID):
            LOGERROR('Somehow we got a KDF object that is not registered')
            LOGERROR('Not going to use it, because if it is not registered, ')
            LOGERROR('it also may not be part of the wallet, yet.')
            raise UnrecognizedCrypto
      elif isinstance(encryptKeyKDF, str):
         kdfID = encryptKeyKDF[:]
         if not KdfObject.kdfIsRegistered(kdfID):
            LOGERROR('Key Deriv Func is not registered.  Cannot create new ')
            LOGERROR('master key without using a known KDF.  Can create a ')
            LOGERROR('new KDF via ')
            LOGERROR('KdfObject().createNewKDF("ROMixOv2", targSec=X, maxMem=Y)')
            raise UnrecognizedCrypto
      else:
         LOGERROR('Bad argument type for "encryptKeyKDF"')
         raise BadInputError


      # Check that we recognize the encryption algorithm
      # This is the algorithm used to encrypt the master key itself
      if not encryptKeyAlgo in KNOWN_CRYPTO:
         LOGERROR('Unrecognized crypto algorithm: %s', encryptKeyAlgo)
         raise UnrecognizedCrypto

      # The masterKeyType is the encryption algorithm that is intended to
      # be used with this key (once it is decrypted to unlock the wallet).
      # This will usually be the same as the encryptKeyAlgo, but I guess 
      # it doesn't have to be
      if masterKeyType==None:
         self.ekeyType = encryptKeyAlgo
      else:
         if not masterKeyType in KNOWN_CRYPTO:
            LOGERROR('Unrecognized crypto algorithm: %s', masterKeyType)
            raise UnrecognizedCrypto
         self.ekeyType = masterKeyType
         
      # Master encryption keys will always be stored with IV
      storedIV = SecureBinaryData().GenerateRandom(8)
      self.encryptInfo = ArmoryCryptInfo(kdfID, encryptKeyAlgo, \
                                         'PASSWORD', storedIV)

      # Create the master key...
      self.masterKeyPlain = SecureBinaryData().GenerateRandom(32)
      self.ekeyID = self.EncryptionKeyToID(self.masterKeyPlain)
      self.masterKeyEncrypted = self.encryptInfo.encrypt(self.masterKeyPlain, \
                                                         passphrase)

      if not withTestString:
         self.testStringPlain = '\x00'*32
         self.testStringEncr  = '\x00'*32
      else:
         rand16 = SecureBinaryData().GenerateRandom(16)
         self.testStringPlain = SecureBinaryData('ARMORYENCRYPTION') + rand16
         testStrIV = self.ekeyID*2  
         if encryptKeyAlgo=='AE256CBC': 
            self.testStringEncr = CryptoAES().EncryptCBC(self.testStringPlain, \
                                                         self.masterKeyPlain, \
                                                         testStrIV)
         elif encryptKeyAlgo=='AE256CFB': 
            self.testStringEncr = CryptoAES().EncryptCFB(self.testStringPlain, \
                                                         self.masterKeyPlain, \
                                                         testStrIV)
         else:
            LOGERROR('Unrecognized encryption algorithm')
      
      self.masterKeyPlain.destroy()

      LOGINFO('Finished creating new master key:')
      LOGINFO('\tKDF:     %s', binary_to_hex(kdfID))
      LOGINFO('\tCrypto:  %s', encryptKeyAlgo)
      LOGINFO('\tTestStr: %s', binary_to_hex(self.testStringPlain[16:]))


#############################################################################
#############################################################################
class ZeroData(object):

   def __init__(self, nBytes=0):
      self.nBytes = nBytes

   def serialize(self):
      return '\x00'*self.nBytes
   
   def unserialize(self, zeroStr):
      self.nBytes = len(zeroStr)
      if not zeroStr.count('\x00')==self.nBytes:
         LOGERROR('Expecting all zero bytes in ZeroData.') 
      return self
      


   


#############################################################################
#############################################################################
class RootRelationship(object):
   """
   Simple Relationships will fit nicely into 68 bytes.  Otherwise, we give
   the idea of RootRelationshipComplex object.  Complex relationships will
   not be used for a long time... but might as well accommodate non-simple
   cases.
   """
   def __init__(self, MofN=None, siblings=[], complexRelate=None):
      if MofN==None:   
         MofN=MULTISIG_UNKNOWN
      self.relType = MofN
      self.relID = None
      self.siblings = siblings
      if len(self.siblings)>3:
         LOGERROR('Cannot have wallet relationships between more than 3 wallets')
         return

      for sib in self.siblings:
         if not len(sib)==20:
            LOGERROR('All siblings must be specified by 20-byte hash160 values')
            return

      self.siblings.sort()


      if MofN==MULTISIG_UNKNOWN:
         LOGDEBUG('Initialized default RootRelationship object')
      else:
         LOGDEBUG('Initialized RootRelationship object: ')
         LOGDEBUG('\tType:     %d-of-%d', self.relType[0], self.relType[1])
         LOGDEBUG('\tSiblings: ')
         for i,sib in enumerate(self.siblings):
            LOGDEBUG('\t\tSiblingRoot%d: %s', i, binary_to_hex(sib))

      # Isn't implemented yet, but we might as well have a placeholder for it
      self.complexRelationship = complexRelate

   def isMultiSig(self):
      return not (MofN in (MULTISIG_UNKNOWN, MULTISIG_NONE, MULTISIG_1of1))

   def serialize(self):
      if not self.complexRelationship: 
         siblingOut = ['\x00'*20]*3
         for i,sib in enumerate(sorted(self.siblings)):
            siblingOut[i] = sib[:]
         bp = BinaryPacker()
         bp.put(UINT32,       self.relType[0])
         bp.put(UINT32,       self.relType[1])
         bp.put(BINARY_CHUNK, siblingOut[0],   widthBytes=20)
         bp.put(BINARY_CHUNK, siblingOut[1],   widthBytes=20)
         bp.put(BINARY_CHUNK, siblingOut[2],   widthBytes=20)
         return bp.getBinaryString()
      else:
         bp = BinaryPacker()
         bp.put(BINARY_CHUNK, '\xff'*4)
         bp.put(BINARY_CHUNK, '\xff'*4)
         bp.put(BINARY_CHUNK, self.complexRelationship.serialize())

   def unserialize(self, theStr):
      bu = makeBinaryUnpacker(theStr)
      M = bu.get(UINT32)
      N = bu.get(UINT32)
      self.siblings = []
      if M==UINT32_MAX and N==UINT32_MAX:
         self.complexRelationship = CplxRelate().unserialize(theStr)
      else:
         for i in range(3):
            sib = bu.get(BINARY_CHUNK, 20)
            if not sib=='\x00'*20:
               self.siblings.append(sib)
      return self


   def hasSibling(self, sibling160):
      return (sibling160 in self.siblings)


   def getRelationshipID(self):
      if self.relID==None:
         self.relID = binary_to_base58(computeChecksum(self.serialize(), 6))
      return self.relID
      

#############################################################################
# Pass in a random binary string, pass out True/False whether it meets
# the criteria for being an acceptable seed
def SipaStretchFunc(theStr, **kwargs):
   """
   For the first round of testing new wallets, we accept any seed
   """
   LOGERROR('Sipa Stretch Function not implemented.  Always return True')
   return True

#############################################################################
#############################################################################
class ArmoryRoot(ArmoryAddress):
      
   FILECODE = 'ROOT'

   def __init__(self):
      super(ArmoryRoot, self).__init__()
      self.wltCreateDate = 0
      self.labelName   = ''
      self.labelDescr  = ''
      self.uniqueIDBin = ''
      self.uniqueIDB58 = ''   # Base58 version of reversed-uniqueIDBin
      self.chainIndexMap = {}
      self.addrMap       = {}  # maps 20-byte addresses to WalletPayloadAddr objects
      self.labelsMap     = {}  # maps 20-byte addresses to user-created labels
      self.chainIndexMap = {}
      self.p2shMap       = {}  # maps raw P2SH scripts to full scripts.

      self.relationship    = RootRelationship(None)
      self.outerCryptInfo  = ArmoryCryptInfo(None)

      self.linearAddr160List = []
      self.lastComputedChainAddr160  = ''
      self.lastComputedChainIndex = 0
      self.highestUsedChainIndex  = 0 
      self.lastSyncBlockNum = 0

      # If this is a "normal" wallet, it is BIP32.  Other types of wallets 
      # (perhaps old Armory chains, will use different name to identify we
      # may do something different)
      self.walletType = "BIP32"

      # Extra data that needs to be encrypted, if 
      self.seedCryptInfo   = ArmoryCryptInfo(None)
      self.bip32seed_plain = SecureBinaryData(0)
      self.bip32seed_encr  = SecureBinaryData(0)
      self.bip32seed_size  = 0

      # FLAGS
      self.isPhoneRoot = False  # don't send from, unless emergency sweep
      self.isFakeRoot = True    # This root has no key data.  Mainly for JBOK
      self.isSiblingRoot = False # observer root of a multi-sig wlt, don't use

      # In the event that some data type identifies this root as its parent AND
      # it identifies itself as critical AND we don't recognize it (such as if
      # you use a colored-coin variant of Armory and then later import the wlt
      # using vanilla Armory), this wallet should be identified as existent 
      # but unusable/disabled, to avoid doing something you shouldn't
      self.isDisabled = False

      # If the user decided to "remove" this wallet, then we simply mark it as
      # "removed" and don't display it or do anything with it.
      self.userRemoved = False



      """
      self.fileTypeStr    = '\xbaWALLET\x00'
      self.magicBytes     = MAGIC_BYTES
      self.version        = ARMORY_WALLET_VERSION  # (Major, Minor, Minor++, even-more-minor)
      self.eofByte        = 0
      self.cppWallet      = None   # Mirror of PyBtcWallet in C++ object
      self.cppInfo        = {}     # Extra info about each address to help sync
      self.watchingOnly   = False
      self.wltCreateDate  = 0

      # Three dictionaries hold all data
      self.addrMap     = {}  # maps 20-byte addresses to PyBtcAddress objects
      self.commentsMap = {}  # maps 20-byte addresses to user-created comments
      self.commentLocs = {}  # map comment keys to wallet file locations
      self.opevalMap   = {}  # maps 20-byte addresses to OP_EVAL data (future)
      self.labelName   = ''
      self.labelDescr  = ''
      self.linearAddr160List = []
      self.chainIndexMap = {}
      if USE_TESTNET:
         self.addrPoolSize = 10  # this makes debugging so much easier!
      else:
         self.addrPoolSize = CLI_OPTIONS.keypool

      # For file sync features
      self.walletPath = ''
      self.doBlockchainSync = BLOCKCHAIN_READONLY
      self.lastSyncBlockNum = 0

      # Private key encryption details
      self.useEncryption  = False
      self.kdf            = None
      self.crypto         = None
      self.kdfKey         = None
      self.defaultKeyLifetime = 10    # seconds after unlock, that key is discarded
      self.lockWalletAtTime   = 0    # seconds after unlock, that key is discarded
      self.isLocked       = False
      self.testedComputeTime=None

      # Deterministic wallet, need a root key.  Though we can still import keys.
      # The unique ID contains the network byte (id[-1]) but is not intended to
      # resemble the address of the root key
      self.uniqueIDBin = ''
      self.uniqueIDB58 = ''   # Base58 version of reversed-uniqueIDBin
      self.lastComputedChainAddr160  = ''
      self.lastComputedChainIndex = 0
      self.highestUsedChainIndex  = 0 

      # All PyBtcAddress serializations are exact same size, figure it out now
      self.pybtcaddrSize = len(PyBtcAddress().serialize())


      # All BDM calls by default go on the multi-thread-queue.  But if the BDM
      # is the one calling the PyBtcWallet methods, it will deadlock if it uses
      # the queue.  Therefore, the BDM will set this flag before making any 
      # calls, which will tell PyBtcWallet to use __direct methods.
      self.calledFromBDM = False

      # Finally, a bunch of offsets that tell us where data is stored in the
      # file: this can be generated automatically on unpacking (meaning it
      # doesn't require manually updating offsets if I change the format), and
      # will save us a couple lines of code later, when we need to update things
      self.offsetWltFlags  = -1
      self.offsetLabelName = -1
      self.offsetLabelDescr  = -1
      self.offsetTopUsed   = -1
      self.offsetRootAddr  = -1
      self.offsetKdfParams = -1
      self.offsetCrypto    = -1
      """


   #############################################################################
   def CreateNewMasterRoot(self, typeStr='BIP32', cryptInfo=None, \
                                 ekeyObj=None, keyData=None, seedSize=20):
      """
      The last few arguments identify how we plan to encrypt the seed and 
      master node information.  We plan to write this stuff to file right
      away, so we want to be able to encrypt it right away.  The cryptInfo
      object tells us how to encrypt it, and the ekeyObj, key and ivData
      objects are what is needed to encrypt the new seed and root immediately
      """


      if not typeStr=='BIP32':
         LOGERROR('Cannot create any roots other than BIP32 (yet)')
         raise NotImplementedError, 'Only BIP32 wallets allowed so far')

      self.walletType = typeStr
      self.wltVersion = ARMORY_WALLET_VERSION
      self.wltSource  = 'ARMORY'.ljust(12, '\x00')

      # Uses Crypto++ PRNG -- which is suitable for cryptographic purposes
      # 16 bytes would probably be enough, but I add 4 extra for some margin.
      # If you don't like it, you can configure it to however many bytes you
      # want.

      # SIPA -- generating N zero bits after 2**N iterations... if N is 
      #         sufficiently small, we can just keep a circular buffer
      #         of 2**N sequetial hashes, and go past 2**N until you find
      #         one.  Then go back 2**N and use that value...

      # Keep generating them until
      LOGINFO('Searching for acceptable BIP32 seed...')
      self.bip32seed_plain  = SecureBinaryData().GenerateRandom(seedSize)
      while not SipaStretchFunc(self.bip32seed_plain, n=12):
         self.bip32seed_plain = SecureBinaryData().GenerateRandom(seedSize)

      LOGINFO('Computing extended key from seed')
      fullExtendedRoot = HDWalletCrypto().ConvertSeedToMasterKey(\
                                                   self.bip32seed_plain)
      
      self.binPrivKey32_Plain = fullExtendedRoot.getPriv()
      self.binPubKey33or65    = fullExtendedRoot.getPub()
      self.binAddr160         = fullExtendedRoot.getHash160().toBinStr()
      self.binChaincode       = fullExtendedRoot.getChain()
      

      # We have a 20-byte seed, but will need to be padded for 16-byte
      # blocksize if we ever need to encrypt it.
      self.bip32seed_size = self.bip32seed_plain.getSize()
      self.bip32seed_plain.padDataMod(cryptInfo.getBlockSize())
  

      # If no crypt info was designated, used default from this wallet file
      if cryptInfo==None:
         LOGINFO('No encryption requested, setting NULL encrypt objects')
         self.seedCryptInfo = ArmoryCryptInfo(None)
         self.bip32seed_encr = SecureBinaryData()
         self.binPrivKey32_Encr  = SecureBinaryData()
      else
         # Assume ivSource is CRYPT_IV_SRC.PUBKEY20[:16]
         self.privCryptInfo = cryptInfo.copy()
         self.seedCryptInfo = cryptInfo.copy()
         self.lock(  ekeyObj=ekeyObj, keyData=keyData)
         self.unlock(ekeyObj=ekeyObj, keyData=keyData)

            
      # FLAGS
      self.uniqueIDB58 = self.computeRootID()
      self.hdwChildID = -1
      self.hdwDepth = -1
      self.hdwIndexList = []
      self.lastComputedChainAddr160  = ''
      self.lastComputedChainIndex = 0
      self.highestUsedChainIndex  = 0 
      self.lastSyncBlockNum = 0
      self.isPhoneRoot = False  # don't send from, unless emergency sweep
      self.isSiblingRoot = False # observer root of a multi-sig wlt, don't use


   #############################################################################
   def getRootID(self, inBase58=True, nbytes=6):
      """ 
      We need some way to distinguish roots from one another, other than their
      20-byte hash.  Ideally, it will be distinct not only based on the Hash160
      value, but also based on the chaincode and chaining algorithm.  This way,
      if there are multiple variants/versions of code which are seeded with 
      the same data, but uses different algorithms, they will be distinguish-
      able.  It's also a good way to verify we are using the same algorithm as
      the code/app that originally produced this wallet.

      For this reason, if a wallet is labeled BIP32, we compute its child with
      index FFFFFFFF, take the first nbytes, and append the address byte to it
      (to identify the network, but put it in the back so that each root ID 
      has a different prefix character).
      """
      if not self.uniqueIDBin:
         endChild = self.spawnChild(0xFFFFFFFF)
         self.uniqueIDBin = endChild.getHash160()[:nbytes]+ADDRBYTE
         self.uniqueIDB58 = binary_to_base58(self.uniqueIDBin)

      return self.uniqueIDB58 if inBase58 else self.uniqueIDBin



   #############################################################################
   lkjlkfdsj
   def spawnChild(self, childID, ekeyObj=None, keyData=None):
      """
      We require some fairly complicated logic here, due to the fact that a
      user with a full, private-key-bearing wallet, may try to generate a new
      key/address without supplying a passphrase.  If this happens, the wallet
      logic gets mucked up -- we don't want to reject the request to
      generate a new address, but we can't compute the private key until the
      next time the user unlocks their wallet.  Thus, we have to save off the
      data they will need to create the key, to be applied on next unlock.
      """
      
      TimerStart('spawnChild')

      if not self.hasChaincode():
         raise KeyDataError, 'No chaincode has been defined to extend chain'

      privAvail = self.getPrivKeyAvailability()
      if privAvail==PRIV_KEY_AVAIL.NextUnlock:
         LOGERROR('Cannot allow multi-level priv key generation while locked')
         LOGERROR('i.e. If your wallet has previously computed m/x and M/x,')
         LOGERROR('but it is currently encrypted, then it can spawn m/x/y by')
         LOGERROR('storing the encrypted version of m/x and its chaincode')
         LOGERROR('and then computing it on next unlock.  But if m/x/y is ')
         LOGERROR('currently in that state, you cannot then spawn m/x/y/z ')
         LOGERROR('until you have unlocked m/x/y once.  This is what is ')
         LOGERROR('meant by "multi-level key generation while locked')
         raise KeyDataError, 'Cannot do multi-level priv key gen while locked'
                              
      wasLocked  = False
      if privAvail==PRIV_KEY_AVAIL.Encrypted:
         unlockSuccess = self.unlock(ekeyObj, keyData)
         if not unlockSuccess:
            raise PassphraseError, 'Incorrect decryption data to spawn child'
         else:
            privAvail = PRIV_KEY_AVAIL.Plain
            wasLocked = True # will re-lock at the end of this operation


      # If we have key data and it's encrypted, it's decrypted by now.
      # extchild has priv key if we have privavail == plain.  Else, we extend
      # only the public part
      if hdwDepth<3:
         childAddr = ArmoryRoot()
      else:
         childAddr = ArmoryAddress()
         
      childAddr.childIdentifier
      extChild  = HDWalletCrypto().ChildKeyDeriv(self.getExtendedKey(), childID)

      # In all cases we compute a new public key and chaincode
      childAddr.binPubKey33or65 = extChild.getPub().copy()
      childAddr.binChaincode    = extChild.getChain().copy()

      if privAvail==PRIV_KEY_AVAIL.Plain:
         # We are extending a chain using private key data (unencrypted)
         childAddr.binPrivKey32_Plain  = extChild.getPriv().copy()
         childAddr.needToDerivePrivKey = False
      elif privAvail==PRIV_KEY_AVAIL.NextUnlock:
         # Copy the parent's encrypted key data to child, set flag
         childAddr.binPrivKey32_Encr = self.binPrivKey32_Encr.copy()
         childAddr.binChaincode      = self.binChaincode.copy()
         childAddr.needToDerivePrivKey = True
      elif privAvail==PRIV_KEY_AVAIL.None:
         # Probably just extending a public key
         childAddr.binPrivKey32_Plain  = SecureBinaryData(0)
         childAddr.needToDerivePrivKey = False
      else:
         LOGERROR('How did we get here?  spawnchild:')
         LOGERROR('   privAvail == %s', privAvail)
         LOGERROR('   encrypt   == %s', self.useEncryption)
         LOGERROR('Bailing without spawning child')
         raise KeyDataError
   
      childAddr.parentHash160      = self.getHash160()
      childAddr.binAddr160         = self.binPubKey33or65.getHash160()
      childAddr.useEncryption      = self.useEncryption
      childAddr.isInitialized      = True
      childAddr.childIdentifier    = childID
      childAddr.hdwDepth           = self.hdwDepth+1
      childAddr.indexList          = self.indexList[:]
      childAddr.indexList.append(childID)

      if childAddr.useEncryption and not childAddr.needToDerivePrivKey:
         # We can't get here without a [valid] decryptKey 
         childAddr.lock(ekeyObj, keyData))
         if not wasLocked:
            childAddr.unlock(ekeyObj, keyData)
            self.unlock(ekeyObj, keyData)
      return childAddr


   #############################################################################
   #def lock(self, ekeyObj=None, encryptKey=None):
      #if self.rootPriv_encr.getSize() > 0:
         #self.rootPriv_encr.destroy()
         #self.bip32seed_encr.destroy()
         #return True
      #elif self.rootPriv_plain.getSize() == 0:
         #LOGERROR('No key data is present to lock')
         #raise EncryptionError
      #elif encryptKey==None:
         #LOGERROR('Need encryption info to lock the wallet')
         #raise EncryptionError
      #elif not self.privCryptInfo.hasStoredIV() or \
           #not self.seedCryptInfo.hasStoredIV()
         #LOGERROR('No stored IV on an ArmoryRoot object')
         #raise InitVectError


      # The ArmoryCryptInfo::encrypt method handles everything as long as 
      # you pass in sufficient information for it to do its thing.  Since
      # this is root which always stores its own IV, we don't need to pass
      # one in
      #self.rootPriv_encr = self.privCryptInfo.encrypt(self.rootPriv_plain, \
                                                      #ekeyObj=ekeyObj, \
                                                      #keyData=encryptKey)
            
      #self.bip32seed_encr = self.seedCryptInfo.encrypt(self.bip32seed_plain, \
                                                       #ekeyObj=ekeyObj, \
                                                       #keyData=encryptKey)
      #return True


   #############################################################################
   def unlock(self, ekeyObj=None, encryptKey=None):
      superUnlocked = super(ArmoryRoot, self).unlock(ekeyObj, encryptKey)

      if superUnlocked and hdwDepth==0:
         # This is a master root which also has seed data
         if self.bip32seed_encr.getSize()  >  0 and \
            self.bip32seed_plain.getSize() == 0:
            self.bip32seed_plain = self.seedCryptInfo.decrypt( \
                                                   self.bip32seed_encr, \
                                                   ekeyObj=ekeyObj, \
                                                   keyData=encryptKey)
            self.bip32seed_plain.resize(self.bip32seed_size)
      return superUnlocked


   #############################################################################
   def lock(self, ekeyObj=None, encryptKey=None):
      superLocked = super(ArmoryRoot, self).lock(ekeyObj, encryptKey)
      if superLocked and hdwDepth==0:
         self.bip32seed_plain.destroy()


   #############################################################################
   def CreateNewJBOKRoot(self, typeStr='BIP32', cryptInfo=None):
      """
      JBOK is "just a bunch of keys," like the original Bitcoin-Qt client 
      (prior to version... 0.8?).   We don't actually need a deterministic 
      part in this root/chain... it's only holding a bunch of unrelated 
      """
      self.isFakeRoot = True
      self.privCryptInfo = cryptInfo.copy()


   #############################################################################
   def advanceHighestIndex(self, ct=1):
      topIndex = self.highestUsedChainIndex + ct
      topIndex = min(topIndex, self.lastComputedChainIndex)
      topIndex = max(topIndex, 0)

      self.highestUsedChainIndex = topIndex
      self.walletFileSafeUpdate( [[WLT_UPDATE_MODIFY, self.offsetTopUsed, \
                    int_to_binary(self.highestUsedChainIndex, widthBytes=8)]])
      self.fillAddressPool()
      
   #############################################################################
   def rewindHighestIndex(self, ct=1):
      self.advanceHighestIndex(-ct)


   #############################################################################
   def peekNextUnusedAddr160(self):
      return self.getAddress160ByChainIndex(self.highestUsedChainIndex+1)

   #############################################################################
   def getNextUnusedAddress(self):
      if self.lastComputedChainIndex - self.highestUsedChainIndex < \
                                              max(self.addrPoolSize-1,1):
         self.fillAddressPool(self.addrPoolSize)

      self.advanceHighestIndex(1)
      new160 = self.getAddress160ByChainIndex(self.highestUsedChainIndex)
      self.addrMap[new160].touch()
      self.walletFileSafeUpdate( [[WLT_UPDATE_MODIFY, \
                                  self.addrMap[new160].walletByteLoc, \
                                  self.addrMap[new160].serialize()]]  )
      return self.addrMap[new160]


   #############################################################################
   def changePrivateKeyEncryption(self, encryptInfoObj):
      

   #############################################################################
   def changeOuterEncryption(self, encryptInfoObj):

   #############################################################################
   def forkObserverChain(self, newWalletFile, shortLabel='', longLabel=''):



   #############################################################################
   def spawnChild(self, childID, decryptKey=None):
      """
      We require some fairly complicated logic here, due to the fact that a
      user with a full, private-key-bearing wallet, may try to generate a new
      key/address without supplying a passphrase.  If this happens, the wallet
      logic gets mucked up -- we don't want to reject the request to
      generate a new address, but we can't compute the private key until the
      next time the user unlocks their wallet.  Thus, we have to save off the
      data they will need to create the key, to be applied on next unlock.
      """

      
      TimerStart('spawnChild')

      if not self.hasChaincode():
         raise KeyDataError, 'No chaincode has been defined to extend chain'

      privAvail = self.getPrivKeyAvailability()
      if privAvail==PRIV_KEY_AVAIL.NextUnlock:
         LOGERROR('Cannot allow multi-level priv key generation while locked')
         LOGERROR('i.e. If your wallet has previously computed m/x and M/x,')
         LOGERROR('but it is currently encrypted, then it can spawn m/x/y by')
         LOGERROR('storing the encrypted version of m/x and its chaincode')
         LOGERROR('and then computing it on next unlock.  But if m/x/y is ')
         LOGERROR('currently in that state, you cannot then spawn m/x/y/z ')
         LOGERROR('until you have unlocked m/x/y once.  This is what is ')
         LOGERROR('meant by "multi-level key generation while locked')
         raise KeyDataError, 'Cannot do multi-level priv key gen while locked'
                              
      wasLocked  = False
      if privAvail==PRIV_KEY_AVAIL.Encrypted:
         if not self.verifyEncryptionKey(decryptKey):
            raise PassphraseError, 'Incorrect passphrase entered to spawn child'
         else:
            self.unlock(decryptKey)
            privAvail = PRIV_KEY_AVAIL.Plain
            wasLocked = True # will re-lock at the end of this operation


      # If we have key data and it's encrypted, it's decrypted by now.
      # extchild has priv key if we have privavail == plain.  Else, we extend
      # only the public part
      childAddr = ArmoryAddress()
      extChild  = HDWalletCrypto().ChildKeyDeriv(self.getExtendedKey(), childID)

      # In all cases we compute a new public key and chaincode
      childAddr.binPubKey33or65 = extChild.getPub().copy()
      childAddr.binChaincode    = extChild.getChain().copy()

      if privAvail==PRIV_KEY_AVAIL.Plain:
         # We are extending a chain using private key data (unencrypted)
         childAddr.binPrivKey32_Plain  = extChild.getPriv().copy()
         childAddr.needToDerivePrivKey = False
      elif privAvail==PRIV_KEY_AVAIL.NextUnlock:
         # Copy the parent's encrypted key data to child, set flag
         childAddr.binPrivKey32_Encr = self.binPrivKey32_Encr.copy()
         childAddr.binChaincode      = self.binChaincode.copy()
         childAddr.needToDerivePrivKey = True
      elif privAvail==PRIV_KEY_AVAIL.None:
         # Probably just extending a public key
         childAddr.binPrivKey32_Plain  = SecureBinaryData(0)
         childAddr.needToDerivePrivKey = False
      else:
         LOGERROR('How did we get here?  spawnchild:')
         LOGERROR('   privAvail == %s', privAvail)
         LOGERROR('   encrypt   == %s', self.useEncryption)
         LOGERROR('Bailing without spawning child')
         raise KeyDataError
   
      childAddr.parentHash160      = extChild.getParentHash160().copy()
      childAddr.binAddr160         = self.binPubKey33or65.getHash160()
      childAddr.useEncryption      = self.useEncryption
      childAddr.isInitialized      = True
      childAddr.childIdentifier    = childID
      childAddr.hdwDepth           = self.hdwDepth+1
      childAddr.indexList          = self.indexList[:]
      childAddr.indexList.append(childID)

      if childAddr.useEncryption and not childAddr.needToDerivePrivKey:
         # We can't get here without a [valid] decryptKey 
         childAddr.lock(decryptKey)
         if not wasLocked:
            childAddr.unlock(decryptKey)
            self.unlock(decryptKey)
      return childAddr


################################################################################
class AddressLabel(object):
  
   FILECODE = 'LABL' 

   def __init__(self, label=''):
      self.set(label)

   def set(self, lbl):
      self.label = toUnicode(lbl)

   def serialize(self):
      bp = BinaryPacker()
      bp.put(BINARY_CHUNK, toBytes(self.label), widthBytes=32)
      return bp.getBinaryString()

   def unserialize(self, theStr):
      self.label = toUnicode(theStr.rstrip('\x00'))
      return label


################################################################################
class TxComment(object):

   FILECODE = 'COMM'

   def __init__(self, comm=''):
      self.set(comm)

   def set(self, comm):
      self.comm = toUnicode(comm)

   def serialize(self):
      bp = BinaryPacker()
      bp.put(BINARY_CHUNK, toBytes(self.comm), widthBytes=32)
      return bp.getBinaryString()

   def unserialize(self, theStr):
      self.comm = toUnicode(theStr.rstrip('\x00'))
      return self


################################################################################
################################################################################
class ArmoryFileHeader(object):
  
   FILECODE = 'HEAD' 

   #############################################################################
   def __init__(self):
      LOGDEBUG('Creating file header')
      self.fileID        = '\xbaARMORY\xab'
      self.armoryVer     = getVersionInt(ARMORY_WALLET_VERSION)
      self.flags         = BitSet(64)
      self.createTime    = UINT64_MAX
      #self.wltName       = u''
      #self.wltDescr      = u''
      #self.wltID         = ''

      # Identifies whether this file is simply
      self.isTransferWallet = False
      self.isSupplemental = False

   #############################################################################
   def serialize(self):
      name  = truncUnicode(self.wltName,  32 )
      descr = truncUnicode(self.wltDescr, 256)
      
      bp = BinaryPacker()
      bp.put(BINARY_CHUNK,    self.fileID,           widthBytes=  8)
      bp.put(UINT32,          self.armoryVer)       #widthBytes=  4
      bp.put(BINARY_CHUNK,    MAGIC_BYTES,           widthBytes=  4)
      #bp.put(BINARY_CHUNK,    self.wltID,            widthBytes=  8)
      bp.put(UINT64,          self.flags.toValue()) #widthBytes=  8
      bp.put(UINT64,          self.createTime)      #widthBytes = 8
      #bp.put(BINARY_CHUNK,    toBytes(name),         widthBytes= 32)
      #bp.put(BINARY_CHUNK,    toBytes(descr),        widthBytes=256)
      return bp.getBinaryString()

   #############################################################################
   def unserialize(self, theStr):
      toUnpack = makeBinaryUnpacker(theStr)
      self.fileID     = bp.get(BINARY_CHUNK,   8)
      self.armoryVer  = bp.get(UINT32)
      magicbytes      = bp.get(BINARY_CHUNK,   4)
      #self.wltID      = bp.get(BINARY_CHUNK,   8)
      flagsInt        = bp.get(UINT64)
      self.createTime = bp.get(UINT64)
      #wltNameBin      = bp.get(BINARY_CHUNK,  32)
      #wltDescrBin     = bp.get(BINARY_CHUNK, 256)

      if not magicbytes==MAGIC_BYTES:
         LOGERROR('This wallet is for the wrong network!')
         LOGERROR('   Wallet is for:  %s ', BLOCKCHAINS[magicbytes])
         LOGERROR('   You are on:     %s ', BLOCKCHAINS[MAGIC_BYTES])
         raise NetworkIDError
      
      self.flags = BitSet().fromValue(flagsInt, 64)
      self.wltName  = toUnicode(wltNameBin.rstrip('\x00'))
      self.wltDescr = toUnicode(wltDescrBin.rstrip('\x00'))
      return self



################################################################################
# Let's take a shot at using inheritance for each of these data types
class WalletEntry(object):
   """
   The wallets will be made up of IFF/RIFF entries. 

   The following comments are for labels & P2SH scripts:

   The goal of this object type is to allow for generic encryption to 
   be applied to wallet entries without regard for what data it is.

   Our root private key only needs to be backed up once, but all of the 
   P2SH scripts should be backed up regularly (and comment fields would be 
   nice to have backed up, too).  The problem is, you don't want to put 
   your whole wallet file into dropbox, encrypted or not.  The solution is
   to have a separate P2SH&Comments file (a wallet without any addresses)
   which can be put in Dropbox.

   The solution is to have a file that can be put in dropbox, and each
   entry is AES encrypted using the 32 bytes of the PUBLIC FINGERPRINT as
   the encryption key.   This allows you to decrypt this entry without 
   even unlocking your wallet, but it does require you to have that (WO)
   wallet in your possession.  Your wallet should NOT be backed up this
   way, thus anyone gaining access to only the P2SH&Comment file would NOT
   have the information needed to decrypt it (and by using the finger-
   print of the address, they can't simply try every public key in the 
   blockchain ... they must have access to at least the watching-only wlt).

   The REQUIRED_TYPES list is all the wallet entry codes that MUST be 
   understood by the reading application in order to move forward 
   reading and using the wallet.  If a data type is in the list, a flag
   will be set in the serialization telling the application that it 
   should throw an error if it does not recognize it.

   Example 1 -- Relationship objects:
      Wallets that are born to be part of M-of-N linked wallets are 
      never used for single-sig addresses.  If an application does
      not implement the relationship type, it should not attempt to 
      use the wallet at all, since it would skip the RLAT code and 
      create single-sig addresses.

   Example 2 -- Colored Coins (not implemented yet):
      If a given wallet handles colored coins, it could be a disaster
      if the application did not recognize that, and let you spend 
      your colored coins as if they were regular BTC.  Thefore, if you
      are going to implement colored coins, you must add that code to
      the REQUIRED_TYPES list.  Then, if vanilla Armory (without colored
      coin support) is used to read the wallet, it will not allow the 
      user to use that wallet
         

   Example 3 -- P2SH Scripts:
      This is borderline, and I may add this to the REQUIRED_TYPES list
      as I get further into implementation.  Strictly speaking, you don't
      *need* P2SH information in order to use the non-P2SH information 
      in the wallet (such as single sig addresses), but you won't 
      recognize much of the BTC that is [partially] available to that 
      wallet if you don't read P2SH scripts.
   
  
   """

   FILECODEMAP = { 'HEAD': ArmoryFileHeader,
                   'ADDR': ArmoryAddress,
                   'ROOT': ArmoryRoot,
                   'LABL': AddressLabel,
                   'COMM': TxComment,
                   'LBOX': MultiSigLockbox,
                   'ZERO': ZeroData, 
                   'RLAT': RootRelationship,
                   'EKEY': EncryptionKey,
                   'MKEY': MultiPwdEncryptionKey,
                   'CRYP': ArmoryCryptInfo,
                   'KDFO': KdfObject,
                   'IDNT': IdentityPublicKey,
                   'SIGN': WltEntrySignature }

   REQUIRED_TYPES = ['ADDR', 'ROOT', 'RLAT']

   #############################################################################
   def __init__(self, weCode=None, wltFileRef=None, wltByteLoc=-1, parentRoot=None, \
                payload=None, encr=ArmoryCryptInfo(None), payloadSize=None):
      self.entryCode       = weCode

      self.wltFileRef      = wltFileRef
      self.wltByteLoc      = wltByteLoc

      self.parentRoot160   = parentRoot
      self.encryptInfo     = encr
      self.initPayload(payload, payloadSize, encr)

      # Default to padding all data in file to modulo 16 (helps with crypto)
      self.setPayloadPadding(16)

      self.lockTimeout  = 10   # seconds after unlock, that key is discarded
      self.relockAtTime = 0    # seconds after unlock, that key is discarded


   #############################################################################
   def initPayload(self, payload, payloadSize=None, encr=ArmoryCryptInfo(None)):
      """
      Note that this overwrites the payload object that isn't set.  So this is
      not good for updating a WE object, only creating a new one...  I tried
      updating this to be more versatile but it got more complicated than I
      had hoped it would be.  For now, I'll leave the complexities to the other
      methods that need it...
      """
      isEncr = (not encr.noEncryption())
      self.payloadPlain    = (None    if isEncr else payload)
      self.payloadEncrypt  = (payload if isEncr else None   )
      self.encryptInfo     = encr

      if not payloadSize==None:
         self.payloadSize = payloadSize
      else:
         if payload==None:
            self.payloadSize=0
         elif isEncr:
            LOGWARN('Defaulting to using size of encrypted payload.  Make ')
            LOGWARN('sure this is what you wanted!  (encrypted payloads ')
            LOGWARN('should almost always have a size specified)')
            self.payloadSize = lenBytes(payload)
         else:
            self.payloadSize = lenBytes(payload.serialize())


   #############################################################################
   def setPayloadPadding(self, padTo):
      self.payloadPadding = padTo
   
   #############################################################################
   def getPayloadSize(self, padded=True):
      out = self.payloadSize
      if padded:
         out = roundUpMod(out, self.payloadPadding)
      return out


   #############################################################################
   def fsync(self):
      if self.wltFileRef==None:
         LOGERROR('Attempted to rewrite WE object but no wlt file ref.')

      if self.wltByteLoc<=0:
         self.wltFileRef.doFileOperation('AddEntry', self)
      else:
         self.wltFileRef.doFileOperation('UpdateEntry', self)

   #############################################################################
   def isEncrypted(self):
      raise 'Notimplemented'


   #############################################################################
   def serialize(self):
      """ 
      Note that if we use padding, that weBytes still refers to the original
      length of the serialized data.  This is so that we know how to separate
      the serialized data from the padding bytes.  However, we still want to 
      checksum the final data written to the file, not the unencrypted data.
      Therefore, the checksum will be computed after the encryption is applied
      making it easy to check the integrity without decrypting.

      Note, we pad out to 16 bytes by default since it saves us a lot of trouble
      when we can later encrypt it in-place if we want to switch -- if we
      start with unencrypted data, but then switch to encrypted, we know that
      the encrypted form will fit in the same place as the unencrypted form.
      We choose 16 by default, since that is the blocksize of AES256. 

      """

      weCode    = self.entryCode
      weBytes   = lenBytes(weData) 

      # Decide whether to write encrypted data
      if self.payloadEncrypt and self.useEncryption():
         weData = self.payloadEncrypt
         isEncrypted = True
      else:  # either payloadPlain or don't desire encryption
         if not self.payloadPlain:
            LOGERROR('Cannot serialize a WalletEntry without a payload!')
            return None
         else:
            isEncrypted = False
            weData = toBytes(self.payloadPlain.serialize())
            if self.payloadPadding>0:
               weData = addPadding(weData, self.payloadPadding, '\x00')

      weChk = computeChecksum(weData)

      # Right now, don't have even close to 32 flags, but room to grow
      flags = BitSet(32)

      if self.entryCode in self.REQUIRED_TYPES:
         flags.setBit(0, True)

      bp = BinaryPacker() 
      bp.put(BINARY_CHUNK, weCode,                           widthBytes= 4)
      bp.put(UINT32,       flags.toValue())                 #widthBytes= 4
      bp.put(UINT32,       weBytes)                         #widthBytes= 4
      bp.put(UINT32,       self.payloadPadding)             #widthBytes= 4
      bp.put(BINARY_CHUNK, self.parentRoot160,               widthBytes=20)
      bp.put(BINARY_CHUNK, self.encryptInfo.serialize(),     widthBytes=32)

      # Put in checksum of header data
      weHeadChk = computeChecksum(bp.getBinaryString())
      bp.put(BINARY_CHUNK, weHeadChk,                        widthBytes= 4)

      # Write the serialized data and its checksum
      bp.put(BINARY_CHUNK, weData)                          #width=weData+Padding
      bp.put(BINARY_CHUNK, weChk,                            widthBytes= 4)

      return bp.getBinaryString()


   #############################################################################
   def unserialize(self, toUnpack, fileOffset=None):
      """
      We will always be reading WalletEntry objs from a single BinaryUnpacker
      object which unpacks the entire file contiguously.  Therefore, the 
      getPosition call will return the same value as the starting byte in
      the file
      """
      if isinstance(toUnpack, BinaryUnpacker):
         binUnpacker = toUnpack
         if fileOffset==None:
            fileOffset = binUnpacker.getPosition()
      else:
         binUnpacker = BinaryUnpacker(toUnpack)
         if fileOffset==None:
            fileOffset=-1

      weHead    = binUnpacker.get(BINARY_CHUNK, 4+4+4+4+20+64)
      weHeadChk = binUnpacker.get(BINARY_CHUNK,  4) 
      weHead    = verifyChecksum(weHead, weHeadChk)
      headerError = False
      if len(weHead)==0:
         LOGERROR('Checksum error in wallet entry HEADER;  could not fix.')
         LOGERROR('Attempting to skip wallet entry')
         headerError = True
         
      
      headUnpacker = BinaryUnpacker(weHead)
      weCode   = headUnpacker.get(BINARY_CHUNK,  4) 
      flagInt  = headUnpacker.get(UINT32)
      weBytes  = headUnpacker.get(UINT32)
      padding  = headUnpacker.get(UINT32)
      weRoot   = headUnpacker.get(BINARY_CHUNK, 20) 
      weCrypto = headUnpacker.get(BINARY_CHUNK, 64)

      if padding>0:
         serBytes = int((weBytes + padding - 1)/padding) * padding
      else:
         serBytes = weBytes

      # Grab the correct amount of data
      weData   = binUnpacker.get(BINARY_CHUNK,  serBytes) 
      weChk    = binUnpacker.get(BINARY_CHUNK,   4) 

      if headerError:
         return None

      flags = BitSet().fromValue(flagInt)
      isCriticalType = flags.getBit(0)


      # Truncate weData to expected length (remove padding), then chksum
      weData = verifyChecksum(weData, weChk)
      if len(weData)==0:
         LOGERROR('Checksum error in wallet entry DATA; could not fix.')
         LOGERROR('Attempting to skip wallet entry')
         return None

      # Now let's save and process

      self.entryCode   = weCode

      encrInfo = ArmoryCryptInfo().unserialize(weCrypto)
      self.initPayload(weData, weBytes, encrInfo)

      # We need to check whether this is even a WE type we recognize
      if not WLTENTRYCLASS.has_key(weCode):
         if isCriticalType:
            LOGERROR('Unrecognized critical entry in wallet file: %s' % weCode)
            LOGERROR('Wallet wil be disabled:  %s', self.wltRootRef.getID())
            self.wltFileRef.setNotUnderstand(True)
            return  None
         else:
            LOGWARN('Unrecognized entry in wallet file: %s' % weCode)
            LOGWARN('Skipping entry...')
            return None

      if not self.encryptInfo.noEncryption():
         # Encrypted data is stored as raw binary string.  
         self.payloadPlain   = ''
         self.payloadEncrypt = weData
      else:
         # Unencrypted data is immediately unserialized into the appropriate obj
         payloadClass   = self.FILECODEMAP[weCode]
         self.payloadPlain   = payloadClass().unserialize(weData[:weBytes])
         self.payloadEncrypt = ''
         self.payloadPlain.wltEntryRef = self


      self.parentRoot160 = weRoot
      self.wltByteLoc = fileOffset
      return self

   #############################################################################
   def setLockTimeout(self, newTimeout):
      self.lockTimeout = newTimeout

   #############################################################################
   def checkLockTimeout(self):
      if self.lockTimeout == 0:
         return 0

      if RightNow() > self.relockAtTime:
         self.lock()


   #############################################################################
   def lock(self, encryptKey=None, encryptIV=None):
      """ 
      It's up to the caller to check beforehand if an encryption key or IV
      is needed, and how to get it.  Check the self.encryptInfo

      WalletEntry encryption is the "outer" encryption, of the entire WE 
      object.  If the data itself has encryption (inner encryption, such
      as for private key data in an ArmoryAddress object), that is irrelevant
      to this method
      """

      if not self.encryptInfo.useEncryption():
         LOGWARN('Trying to lock unencrypted data...?')
         return

      # Check for the very simple locking case:
      if len(self.payloadEncrypt) > 0:
         if encryptKey==None:
            # We have encrypted form, and no key spec'd, just destroy plain
            self.payloadPlain = None
            return
         else:
            # We are relocking with a different encryption key
            LOGWARN('Specified encryption key with data already encrypted')
            LOGWARN('Make sure you meant to re-encrypt the WE data this way')
            # Will re-encrypt in next conditional

      if not self.payloadPlain:
         LOGERROR('Nothing to encrypt')

         
      plain = self.payloadPlain.serialize()
      plain = addPadding(plain, self.encryptInfo.getBlockSize())
      self.payloadEncrypt = self.encryptInfo.encrypt(plain, encryptKey, encryptIV)
      self.payloadPlain = None
      return

   #############################################################################
   def unlock(self, encryptKey, encryptIV=None):
      """ 
      It's up to the caller to check beforehand if an encryption key or IV
      is needed, and how to get it.  Check the self.encryptInfo

      WalletEntry encryption is the "outer" encryption, of the entire WE 
      object.  If the data itself has encryption (inner encryption, such
      as for private key data in an ArmoryAddress object), that is irrelevant
      to this method
      """
      if not self.encryptInfo.useEncryption():
         LOGWARN('Trying to unlock unencrypted data...?')
         return

        
      if not self.payloadPlain==None:
         # Already unlocked
         return

      if self.payloadEncrypt==None:
         LOGERROR('No payload to decrypt')
         return 
         

      plain = self.encryptInfo.decrypt(self.payloadEncrypt, encryptKey, encryptIV)
      plain = plain[:self.payloadSize]

      payloadClass = self.FILECODEMAP[self.entryCode]
      self.payloadPlain = payloadClass().unserialize(plain)
      self.payloadPlain.wltEntryRef = self




   #############################################################################
   def removeEncryption(self, oldKey, oldIV=None):
      raise NotImplementedError


   #############################################################################
   def pprintOneLine(self, nIndent=0):
      fmtField = lambda lbl,val,wid: '(%s %s)'%(lbl,str(val)[:wid].rjust(wid))
      print fmtField('', self.entryCode, 4),
      print fmtField('in', self.self.wltFileRef.filepath.basename(), 4),

      #toPrint = [self.entryCode, \
                 #self.wltFileRef.path.basename, \
                 #self.wltByteLoc, \
                 #binary_to_hex(self.parentRoot160[:4]), \

      #self.entryCode       = weCode

      #self.wltFileRef      = wltFileRef
      #self.wltByteLoc      = wltByteLoc

      #self.parentRoot160   = parentRoot
      #self.encryptInfo     = encr
      #self.initPayload(payload, payloadSize, encr)

      # Default to padding all data in file to modulo 16 (helps with crypto)
      #self.setPayloadPadding(16)

      #self.lockTimeout  = 10   # seconds after unlock, that key is discarded
      #self.relockAtTime = 0    # seconds after unlock, that key is discarded



   #############################################################################
   def deleteThisEntry(self, doFsync=True):
      """ 
      Static method for creating deleted wallet-entry objects.  DeleteData can
      either be a number (the number of zero bytes to write, or it can be an
      existing WalletEntry object, where we will simply figure out how big the
      payload is an create a new object with the same number of zero bytes.
      """

      nBytes = self.getPayloadSize(padded=True)
      self.entryCode = 'ZERO'
      self.encryptInfo = ArmoryCryptInfo(None)
      self.payloadPlain = ZeroData(nBytes)
      self.payloadEncrypt = None
      self.payloadSize = nBytes
      self.payloadPadding = 0

      if not self.wltFileRef==None and self.wltByteLoc>0 and doFsync:
         self.fsync()

      return self


################################################################################
################################################################################
class ArmoryWalletFile(object):

   def __init__(self):

      if not os.path.exists(filepath) and not createNew:
         LOGERROR('Attempted to open a wallet file that does not exist!')
         raise FileExistsError

      self.fileHeader = ArmoryFileHeader()

      # We will queue updates to the wallet file, and later apply them  
      # atomically to avoid corruption problems
      self.updateQueue   = []
      self.lastFilesize  = -1

      # WalletEntry objects may request an update, but that update is not 
      # applied right away.  This variable will be incremented on every
      # call to applyUpdates(), so WE objects know when it's done
      self.updateCount  = 0

      # We will need a bunch of different pathnames for atomic update ops
      self.walletPath        = filepath
      self.walletPathBackup  = self.getWalletPath('backup')
      self.walletPathUpdFail = self.getWalletPath('update_unsuccessful')
      self.walletPathBakFail = self.getWalletPath('backup_unsuccessful')

      # Last synchronized all chains to this block
      self.lastSyncBlockNum = 0

      # All wallet roots based on "standard" BIP 32 usage:
      #    rootMap[0] ~ Map of all zeroth-order roots, derived from seeds
      #    rootMap[1] ~ Map of all wallets for all base roots
      #    rootMap[2] ~ Map of internal/external chains of all wallets.
      # Maps are indexed by 20-byte ID (the address/hash160 they would have
      # if they were to be used to receive funds, but they are not in these
      # maps if they are ever used to receive funds -- all such addresses 
      # exist at the next level)
      self.rootMapBIP32 = [{}, {}, {}]

      # If there are other roots (such as old Armory wallets, or JBOK wlts,
      # etc) we will need to track them using other roots.  In the case of
      # old Armory wallets, the original index=-1 address will be included
      # in this map.  For importing old Bitcoin-Qt wallets, we will create 
      # a root with a random ID to hold "just a bunch of keys" (JBOK).
      self.rootMapOther = {}

      # List of all master encryption keys in this wallet (and also the 
      # data needed to understand how to decrypt them, probably by KDF)
      self.ekeyMap = {}

      # List of all KDF objects -- probably created based on testing the 
      # system speed when the wallet was created
      self.kdfMap  = {}

      # Master address list of all wallets/roots/chains that could receive BTC
      self.masterAddrMap  = {}

      # If != None, it means that this wallet holds only a subset of data 
      # in the parent file.  Probably just addr/tx comments and P2SH scripts
      self.masterWalletRef = None

      # Alternatively, if this is a master wallet it may have a supplemental
      # wallet for storing
      self.supplementalWltPath = None
      self.supplementalWltRef = None

      # Default encryption settings for "outer" encryption (if we want to
      # encrypt the entire WalletEntry, not just the private keys
      self.defaultOuterEncrypt = ArmoryCryptInfo(None)
      self.defaultInnerEncrypt = ArmoryCryptInfo(None)

      # This file may actually be used for a variety of wallet-related 
      # things -- such as transferring observer chains, exchanging linked-
      # wallet info, containing just comments/labels/P2SH script -- but 
      # not actually be used as a proper wallet.
      self.isTransferWallet = False
      self.isSupplemental = False


      # These flags are ONLY for unit-testing the atomic file operations
      self.interruptTest1  = False
      self.interruptTest2  = False
      self.interruptTest3  = False





   #############################################################################
   def createNewKDFObject(self, kdfAlgo='ROMixOv2', \
                                targSec=0.25, \
                                maxMem=32*1024*1024,
                                writeToFile=True):

      """
      ROMixOv2 is ROMix-over-2 -- it's the ROMix algorithm as described by 
      Colin Percival, but using only 1/2 of the number of LUT ops, in order
      to bring down computation time in favor of more memory usage.

      If we had access to Scrypt, it could be an option here.  ROMix was 
      chosen due to simplicity despite its lack of flexibility
      """
      LOGINFO('KDF Target (time,RAM)=(%0.3f,%d)', kdfTargSec, kdfMaxMem)
      
      if kdfAlgo.lower()=='romixov2':
         
         kdf = KdfRomix()
         kdf.computeKdfParams(targetSec, long(maxMem))
   
         mem   = kdf.getMemoryReqtBytes()
         nIter = kdf.getNumIterations()
         slt   = SecureBinaryData(kdf.getSalt().toBinStr())

         newKDF   = KdfObject(kdfAlgo, memReqd=mem, numIter=nIter, salt=slt)
         newWE    = WalletEntry(self, payload=newKDF)
         newKdfID = newKDF.getKdfID()
   
         if writeToFile and not self.kdfMap.has_key(newKdfID):
            self.doFileOperation('Append', newWE)

         self.kdfMap[newKdfID] = newKDF
         ArmoryCryptInfo.registerKDF(newKDF)


   
         
   #############################################################################
   def changePrivateKeyEncryption(self, encryptInfoObj):
      raise 'Notimplemented'   

   #############################################################################
   def changeOuterEncryption(self, encryptInfoObj):
      raise 'Notimplemented'   

   def findAllEntriesUsingObject(self, objID):
      """
      Use this to identify whether certain objects, such as KDF objects, are 
      no longer being used and can be removed (or for some other reason)
      """
      raise NotImplementedError

   #############################################################################
   def hasKDF(self, kdfID):
      return self.kdfMap.has_key(kdfID)

   #############################################################################
   def hasCryptoKey(self, ekeyID):
      return self.ekeyMap.has_key(ekeyID)

   #############################################################################
   def mergeWalletFile(self, wltOther, rootsToAbsorb='ALL'):
      """
      Just like in git, WltA.mergeWalletFile(WltB) means we want to pull all 
      the keys from WltB into WltA and leave WltB untouched.
      """

      if isinstance(wltOther, basestring):
         # Open wallet file
         if not os.path.exists(wltOther):
            LOGERROR('Wallet to merge does not exist: %s', filepath)
            raise WalletExistsError
         wltOther = ArmoryWalletFile.readWalletFile(filepath)


      rootRefList = []

      #
      for level in range(3):
         rootMap = wltOther.rootMap[level]
         for rootID,root in rootMap.iteritems():
            if rootsToAbsorb=='ALL' or rootID in rootsToAbsorb:
               rootRefList.append(rootID, root)



      # We need to not only copy over all addr and sub-roots, but
      # also all KDF objects and any other things in the file that ref
      # this root/addr (also any relationship objects and any roots
      # related to that, as well)
      i = 0
      procRootAlready = set([])
      while i<len(rootRefList):
         rootID,root = rootRefList[i]
         if rootID in procRootAlready:
            continue

         procRootAlready.add(rootID)

         
         addFileOperationToQueue

         if root.relationship.isMultiSig:
            # Make sure to merge the sibling wallets, too
            for sib in root.relationship.siblingList:
               if not sib.rootID in rootRefList:
                  LOGINFO('Adding sibling to root-merge list')
               rootRefList.add(sib.rootID)




   #############################################################################
   def mergeRootFromWallet(self, filepath, rootID, weTypesToMerge=['ALL']):
      # Open wallet file
      if not os.path.exists(filepath):
         LOGERROR('Wallet to merge does not exist: %s', filepath)

      with open(filepath, 'rb') as f:
         bu = BinaryUnpacker(f.read())

      while not bu.isEndOfStream():
         weObj = readWalletEntry(bu)
         if weObj.payload.root160:
            raise 'Notimplemented'   
         if weTypesToMerge[0].lower()=='all' or weObj.entryCode in weTypesToMerge:
            self.addFileOperationToQueue('Append', weObj)
      

   #############################################################################
   def loadExternalInfoWallet(self, filepath):
      """
      After this wallet is loaded, we may want to merge, in RAM only, another
      wallet file containing only P2SH scripts and comments.  The reason for
      this is that our root private key only needs to be backed up once, but 
      P2SH scripts MUST be backed up regularly (and comment fields would be 
      nice to have backed up, too).  The problem is, you don't want to put 
      your whole wallet file into dropbox, encrypted or not.  The solution is
      to have a separate P2SH&Comments file (a wallet without any addresses)
      which can be put in Dropbox.  And encrypt that file with information
      in the wathcing-only wallet -- something that you have even without 
      unlocking your wallet, but an attacker does not if they compromise your
      Dropbox account.
      """

      if not exists(filepath):
         LOGERROR('External info file does not exist!  %s' % filepath)

      self.externalInfoWallet =  PyBtcWallet().readWalletFile(filepath)


   #############################################################################
   def readWalletEntry(self, toUnpack):
      we = WalletEntry().unserialize(toUnpack)


         
        

   #############################################################################
   def doFileOperation(self, operationType, theData, loc=None):
      if not len(self.updateQueue)==0:
         LOGERROR('Wallet update queue not empty!  Applying previously')
         LOGERROR('queued operations before executing this update.')

      self.addFileOperationToQueue(operationType, theData, loc)
      self.applyUpdates()
          

   #############################################################################
   def addFileOperationToQueue(self, operationType, theData, fileLoc=None):
      """
      This will add lower-level data to the queue to be applied in a
      batch operation.  Two ways to do direct, low-level operations, 
      a shortcut method for operating with WalletEntry objects.

         (opType, theData) ~ ('Append',      'Some data to append')
         (opType, theData) ~ ('Modify',      'Overwrite beginning of file', 0)
         (opType, theData) ~ ('Modify',      'Overwrite something else', N)
         (opType, theData) ~ ('AddEntry',    WalletEntryObj)
         (opType, theData) ~ ('UpdateEntry', WalletEntryObj)
         (opType, theData) ~ ('DeleteEntry', WalletEntryObj)
         (opType, theData) ~ ('DeleteEntry', WalletEntryStartByte)

      If one of the "entry" versions is used, it will simply pull the
      necessary information out of the object and do an "Append' or "Modify'
      as necessary.
      """
         
      
      isWltEntryObj = isinstance(theData, WalletEntry)

      # The data to eventually be added to the file, or overwrite previous data
      newData = None

      # Convert the "___Entry" commands into the lower-level Append/Modify cmds
      if operationType.lower()=='addentry':
         # Add a new wallet entry to this wallet file
         if not isWltEntryObj:
            LOGERROR('Must supply WalletEntry object to use "addEntry" cmd')
            raise BadInputError
         if data already in wallet:
            skip
         newData = theData.serialize()
         operationType = 'Append'
      elif operationType.lower()=='updateentry':
         # Update an existing entry -- delete and append if size changed
         if not isWltEntryObj:
            LOGERROR('Must supply WalletEntry object to use "updateEntry" cmd')
            raise BadInputError
         newData = theData.serialize()
         oldData = self.readWalletEntry(theData.wltByteLoc).serialize()
         if len(newData)==len(oldData):
            fileLoc = theData.wltByteLoc
            operationType = 'Modify'
         else:
            LOGINFO('WalletEntry replace != size (%s).  ', theData.entryCode)
            LOGINFO('Delete&Append')
            self.addFileOperationToQueue('DeleteEntry', theData.wltByteLoc)
            operationType = 'Append'
      elif operationType.lower()=='deleteentry':
         # Delete an entry from the wallet
         fileLoc = theData.wltByteLoc if isWltEntryObj else theData
         if not isinstance(theData, (int,long)):
            LOGERROR('Delete entry only using WltEntry object or start byte')
            return

         oldData = self.readWalletEntry(fileLoc).serialize()
         totalBytes = len(oldData)
         # TODO figure out how to set up the deleted entry
         delBytes = oldData.getPayloadSize(padding=True)
         newData = ZeroData(delBytes).serialize()
         operationType = 'Modify'
            
         if isWltEntryObj:
            LOGERROR('TODO: figure out what I want to do with deleted WltEntry')
            theData.wltByteLoc = -1

      else:
         if not isinstance(theData, basestring):
            LOGERROR('Can only add/update wallet data with string or unicode type!')
            return

         newData = theData[:]

      #####
      # This is where it actually gets added to the queue.
      if operationType.lower()=='append':
         if isWltEntryObj:
            theData.wltByteLoc =  self.lastFilesize
         self.lastFilesize += len(newData)
         self.updateQueue.append([WLT_UPDATE_ADD, newData])
   
      elif operationType.lower()=='modify':
         if not fileLoc:
            LOGERROR('Must supply start byte of modification')
            raise BadInputError
         self.updateQueue.append([WLT_UPDATE_MODIFY, [newData, fileLoc]])

      #####
      # Tell the WalletEntry object when to expect its internal state to be 
      # consistent with the wallet file
      if isWltEntryObj:
         theData.syncWhenUpdateCount = self.updateCount + 1
         
         

   #############################################################################
   def getWalletPath(self, nameSuffix=None):
      fpath = self.walletPath

      if self.walletPath=='':
         fpath = os.path.join(ARMORY_HOME_DIR, 'armory_wallet_%s.bin' % self.uniqueIDB58)

      if nameSuffix:
         name,ext = os.path.splitext(fpath)
         joiner = '' if name.endswith('_') else '_'
         fpath = name + joiner + nameSuffix + ext
      return fpath


   #############################################################################
   def applyUpdates(self):
            
      """
      When we want to add data to the wallet file, we will do so in a completely
      recoverable way.  We define this method to make sure a backup exists when
      we start modifying the file, and keep a flag to identify when the wallet
      might be corrupt.  If we ever try to load the wallet file and see another
      file with the _update_unsuccessful suffix, we should instead just restore
      from backup.

      Similarly, we have to update the backup file after updating the main file
      so we will use a similar technique with the backup_unsuccessful suffix.
      We don't want to rely on a backup if somehow *the backup* got corrupted
      and the original file is fine.  THEREFORE -- this is implemented in such
      a way that the user should know two things:

         (1) No matter when the power goes out, we ALWAYS have a uncorrupted
             wallet file, and know which one it is.  Either the backup is safe,
             or the original is safe.  Based on the flag files, we know which
             one is guaranteed to be not corrupted.
         (2) ALWAYS DO YOUR FILE OPERATIONS BEFORE SETTING DATA IN MEMORY
             You must write it to disk FIRST using this SafeUpdate method,
             THEN give the new data to the user -- never give it to them
             until you are sure that it was written safely to disk.

      Number (2) is easy to screw up because you plan to write the file just
      AFTER the data is created and stored in local memory.  But an error
      might be thrown halfway which is handled higher up, and instead the data
      never made it to file.  Then there is a risk that the user uses their
      new address that never made it into the wallet file.
      """

      if not os.path.exists(self.walletPath):
         raise FileExistsError, 'No wallet file exists to be updated!'

      if len(updateList)==0:
         return False

      # Make sure that the primary and backup files are synced before update
      self.doWalletFileConsistencyCheck()

      # Split the queue into updates and modifications.  
      toAppend = []
      toModify = []
      for modType,rawData in updateList:
         if(modType==WLT_UPDATE_ADD):
            toAppend.append(rawData)
         elif(modType==WLT_UPDATE_MODIFY):
            toModify.append(rawData)

      # We need to safely modify both the main wallet file and backup
      # Start with main wallet
      touchFile(self.walletPathUpdFail)

      try:
         wltfile = open(self.walletPath, 'ab')
         wltfile.write(''.join(toAppend))
         wltfile.close()

         # This is for unit-testing the atomic-wallet-file-update robustness
         if self.interruptTest1: raise InterruptTestError

         wltfile = open(self.walletPath, 'r+b')
         for loc,replStr in toModify:
            wltfile.seek(loc)
            wltfile.write(replStr)
         wltfile.close()

      except IOError:
         LOGEXCEPT('Could not write data to wallet.  Permissions?')
         shutil.copy(self.walletPathBackup, self.walletPath)
         os.remove(self.walletPathUpdFail)
         return False

      # Write backup flag before removing main-update flag.  If we see
      # both flags, we know file IO was interrupted RIGHT HERE
      touchFile(self.walletPathBakFail)

      # This is for unit-testing the atomic-wallet-file-update robustness
      if self.interruptTest2: raise InterruptTestError

      os.remove(self.walletPathUpdFail)

      # Modify backup
      try:
         # This is for unit-testing the atomic-wallet-file-update robustness
         if self.interruptTest3: raise InterruptTestError

         backupfile = open(self.walletPathBackup, 'ab')
         backupfile.write(''.join(toAppend))
         backupfile.close()

         backupfile = open(self.walletPathBackup, 'r+b')
         for loc,replStr in toModify:
            backupfile.seek(loc)
            backupfile.write(replStr)
         backupfile.close()

      except IOError:
         LOGEXCEPT('Could not write backup wallet.  Permissions?')
         shutil.copy(self.walletPath, self.walletPathBackup)
         os.remove(self.walletPathUpdFail)
         return False

      os.remove(self.walletPathBakFail)
      self.updateCount += 1
      self.updateQueue = []

      return True



   #############################################################################
   def doWalletFileConsistencyCheck(self):
      """
      First we check the file-update flags (files we touched/removed during
      file modification operations), and then restore the primary wallet file
      and backup file to the exact same state -- we know that at least one of
      them is guaranteed to not be corrupt, and we know based on the flags
      which one that is -- so we execute the appropriate copy operation.

      ***NOTE:  For now, the remaining steps are untested and unused!

      After we have guaranteed that main wallet and backup wallet are the
      same, we want to do a check that the data is consistent.  We do this
      by simply reading in the key-data from the wallet, unserializing it
      and reserializing it to see if it matches -- this works due to the
      way the PyBtcAddress::unserialize() method works:  it verifies the
      checksums in the address data, and corrects errors automatically!
      And it's part of the unit-tests that serialize/unserialize round-trip
      is guaranteed to match for all address types if there's no byte errors.

      If an error is detected, we do a safe-file-modify operation to re-write
      the corrected information to the wallet file, in-place.  We DO NOT
      check comment fields, since they do not have checksums, and are not
      critical to protect against byte errors.
      """

      if not os.path.exists(self.walletPath):
         raise FileExistsError, 'No wallet file exists to be checked!'

      if not os.path.exists(self.walletPathBackup):
         # We haven't even created a backup file, yet
         LOGDEBUG('Creating backup file %s', self.walletPathBackup)
         touchFile(self.walletPathBakFail)
         shutil.copy(self.walletPath, self.walletPathBackup)
         os.remove(self.walletPathBakFail)
         return

      if os.path.exists(self.walletPathBakFail) and os.path.exists(self.walletPathUpdFail):
         # Here we actually have a good main file, but backup never succeeded
         LOGWARN('***WARNING: error in backup file... how did that happen?')
         shutil.copy(self.walletPath, self.walletPathBackup)
         os.remove(self.walletPathUpdFail)
         os.remove(self.walletPathBakFail)
      elif os.path.exists(self.walletPathUpdFail):
         LOGWARN('***WARNING: last file operation failed!  Restoring wallet from backup')
         # main wallet file might be corrupt, copy from backup
         shutil.copy(self.walletPathBackup, self.walletPath)
         os.remove(self.walletPathUpdFail)
      elif os.path.exists(self.walletPathBakFail):
         LOGWARN('***WARNING: creation of backup was interrupted -- fixing')
         shutil.copy(self.walletPath, self.walletPathBackup)
         os.remove(self.walletPathBakFail)


   #############################################################################
   def createAndAddNewMasterSeed(self, withEncryption=True, \
                                         nonDefaultEncrInfo=None):
      if withEncryption and self.isLocked():
         LOGERROR('Trying to add new encrypted root to wallet while locked')
         raise EncryptionError

      

      
   #############################################################################
   def addPregeneratedMasterSeed(self, plainSeed=None, encrSeed=None):


   #############################################################################
   def addPregeneratedMasterRoot(self, plainSeed=None, encrSeed=None):


   #############################################################################
   def createNewLinkedWallet(self, typeStr, withEncrypt,):

   #############################################################################
   def readWalletFile(self, filename):

   #############################################################################
   def writeFreshWalletFile(self, path, newName='', newDescr=''):



   #############################################################################
   # 
   def CreateNewWalletFile(self, 
                           createNewRoot=True, \
                           securePassphrase=None, \
                           kdfTargSec=DEFAULT_COMPUTE_TIME_TARGET, \
                           kdfMaxMem=DEFAULT_MAXMEM_LIMIT, \
                           defaultInnerEncrypt=None, \
                           defaultOuterEncrypt=None, \
                           doRegisterWithBDM=True, \
                           ):
                             #newWalletFilePath=None, \
                             #plainRootKey=None, \
                             ##withEncrypt=True, securePassphrase=None, \
                             #kdfTargSec=DEFAULT_COMPUTE_TIME_TARGET, \
                             #kdfMaxMem=DEFAULT_MAXMEM_LIMIT, \
                             #shortLabel='', longLabel='', isActuallyNew=True, \
                             #doRegisterWithBDM=True):
      raise NotImplementedError
      """

      We skip the atomic file operations since we don't even have
      a wallet file yet to safely update.

      DO NOT CALL THIS FROM BDM METHOD.  IT MAY DEADLOCK.
      """

      
      if self.calledFromBDM:
         LOGERROR('Called createNewWallet() from BDM method!')
         LOGERROR('Don\'t do this!')
         return None

      LOGINFO('***Creating new deterministic wallet')

      #####
      # Create a new KDF -- we need one for just about every wallet, regardless
      # of whether we are using encryption (yet).  The new KDF will be stored
      # with the wallet, and used by default whenever we want to encrypt 
      # something
      LOGDEBUG('Creating new KDF object')
      newKDF = KdfObject().createNewKDF('ROMixOv2', kdfTargSec, kdfMaxMem)
      self.kdfMap[newKDF.getKdfID()] = newKDF

      #####
      # If a secure passphrase was supplied, create a new master encryption key
      LOGDEBUG('Creating new master encryption key')
      if not securePassphrase==None:
         securePassphrase = SecureBinaryData(securePassphrase)
         newEKey = EncryptionKey().CreateNewMasterKey(newKDF, \
                                                   'AE256CFB', \
                                                   securePassphrase)
         self.ekeyMap[newEKey.getEncryptionKeyID()] = newEKey

      #####
      # If requested (usually is), create new master seed and the first wlt
      LOGDEBUG('Creating new master root seed & node')
      if createNewRoot:
         newRoot = ArmoryRoot().CreateNewMasterRoot()
      



      # Create the root address object
      rootAddr = PyBtcAddress().createFromPlainKeyData( \
                                             plainRootKey, \
                                             IV16=IV, \
                                             willBeEncr=withEncrypt, \
                                             generateIVIfNecessary=True)
      rootAddr.markAsRootAddr(chaincode)

      # This does nothing if no encryption
      rootAddr.lock(self.kdfKey)
      rootAddr.unlock(self.kdfKey)

      firstAddr = rootAddr.extendAddressChain(self.kdfKey)
      first160  = firstAddr.getAddr160()

      # Update wallet object with the new data
      self.useEncryption = withEncrypt
      self.addrMap['ROOT'] = rootAddr
      self.addrMap[firstAddr.getAddr160()] = firstAddr
      self.uniqueIDBin = (ADDRBYTE + firstAddr.getAddr160()[:5])[::-1]
      self.uniqueIDB58 = binary_to_base58(self.uniqueIDBin)
      self.labelName  = shortLabel[:32]
      self.labelDescr  = longLabel[:256]
      self.lastComputedChainAddr160 = first160
      self.lastComputedChainIndex  = firstAddr.chainIndex
      self.highestUsedChainIndex   = firstAddr.chainIndex-1
      self.wltCreateDate = long(RightNow())
      self.linearAddr160List = [first160]
      self.chainIndexMap[firstAddr.chainIndex] = first160

      # We don't have to worry about atomic file operations when
      # creating the wallet: so we just do it naively here.
      self.walletPath = newWalletFilePath
      if not newWalletFilePath:
         shortName = self.labelName .replace(' ','_')
         # This was really only needed when we were putting name in filename
         #for c in ',?;:\'"?/\\=+-|[]{}<>':
            #shortName = shortName.replace(c,'_')
         newName = 'armory_%s_.wallet' % self.uniqueIDB58
         self.walletPath = os.path.join(ARMORY_HOME_DIR, newName)

      LOGINFO('   New wallet will be written to: %s', self.walletPath)
      newfile = open(self.walletPath, 'wb')
      fileData = BinaryPacker()

      # packHeader method writes KDF params and root address
      headerBytes = self.packHeader(fileData)

      # We make sure we have byte locations of the two addresses, to start
      self.addrMap[first160].walletByteLoc = headerBytes + 21

      fileData.put(BINARY_CHUNK, '\x00' + first160 + firstAddr.serialize())


      # Store the current localtime and blocknumber.  Block number is always 
      # accurate if available, but time may not be exactly right.  Whenever 
      # basing anything on time, please assume that it is up to one day off!
      time0,blk0 = getCurrTimeAndBlock() if isActuallyNew else (0,0)

      # Don't forget to sync the C++ wallet object
      self.cppWallet = Cpp.BtcWallet()
      self.cppWallet.addAddress_5_(rootAddr.getAddr160(), time0,blk0,time0,blk0)
      self.cppWallet.addAddress_5_(first160,              time0,blk0,time0,blk0)

      # We might be holding the wallet temporarily and not ready to register it
      if doRegisterWithBDM:
         TheBDM.registerWallet(self.cppWallet, isFresh=isActuallyNew) # new wallet


      newfile.write(fileData.getBinaryString())
      newfile.close()

      walletFileBackup = self.getWalletPath('backup')
      shutil.copy(self.walletPath, walletFileBackup)

      # Lock/unlock to make sure encrypted keys are computed and written to file
      if self.useEncryption:
         self.unlock(secureKdfOutput=self.kdfKey)

      # Let's fill the address pool while we are unlocked
      # It will get a lot more expensive if we do it on the next unlock
      if doRegisterWithBDM:
         self.fillAddressPool(self.addrPoolSize, isActuallyNew=isActuallyNew)

      if self.useEncryption:
         self.lock()



      SERIALIZEEVERYTHINGINTO THE FILE
      self.writeFreshWalletFile(filepath)
      return self
