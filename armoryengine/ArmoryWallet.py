

################################################################################
CRYPT_KEY_SRC = enum('PASSWORD', 'MULTIPWD', 'PARCHAIN', 'EKEY_OBJ', 'RAW_EKEY')
CRYPT_IV_SRC  = enum('STOREDIV', 'PUBKEY20')
NULLSTR = lambda numBytes: '\x00'*numBytes
NULLSBD = lambda: SecureBinaryData(0)
NULLKDF = NULLSTR(8)
KNOWN_CRYPTO = {'AE256CFB': {'blocksize': 16, 'keysize': 32}, \
                'AE256CBC': {'blocksize': 16, 'keysize': 32} }

def roundUpMod(val, mod):
   return ((int(val)- 1) / mod + 1) * mod


def padString(s, mod, pad='\x00'):
   currSz = len(s)
   needSz = roundUpMod(currSz, mod)
   return s + pad*(needSz-currSz)


# We only store 8 bytes for each IV field, though we usually need 16 or 32 
@VerifyArgTypes(iv=SecureBinaryData)
def stretchIV(iv, sz):
   if sz > 64:
      raise BadInputError('Should never have to stretch an IV past 64 bytes!')

   # Truncate if too big
   newIV = iv.toBinStr()[:sz]

   # Hash if too small
   if len(newIV) < sz:
      newIV = sha512(newIV)[:sz]

   return SecureBinaryData(newIV)
      

@VerifyArgTypes(rawKey=SecureBinaryData)
def calcEKeyID(rawKey):
   # We use HMAC instead of regular checksum, solely because it's designed
   # for hashing secrets, though I don't think it's really necessary here 
   # (especially for a truncated hash).
   return HMAC_SHA512(rawKey.toBinStr(), "ArmoryKeyID")[:8]



################################################################################
class WalletEntry(object):
   """
   The wallets will be made up of IFF/RIFF entries. 


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
                   'KDFO': KdfObject,
                   'IDNT': IdentityPublicKey,
                   'SIGN': WltEntrySignature }

   REQUIRED_TYPES = ['ADDR', 'ROOT', 'RLAT']

   #############################################################################
   def __init__(self, wltFileRef=None, wltByteLoc=-1, reqdBit=False,    
              parentRoot=None, cryptInfo=None, serPayload=None, defaultPad=256):
      self.wltFileRef = wltFileRef
      self.wltByteLoc = wltByteLoc
      self.isRequired = reqdBit
      self.parentRoot = parentRoot
      self.cryptInfo  = cryptInfo
      self.serPayload = serPayload
      self.rsecCode   = rsecCode 
      self.isOpaque   = False
      self.defaultPad = defaultPad
         

   #############################################################################
   @staticmethod
   def UnserializeEntry(toUnpack, parentWlt, fileOffset, **decryptKwargs):
      toUnpack = makeBinaryUnpacker(toUnpack)

      self.wltFileRef   = parentWlt
      self.wltStartByte = fileOffset 

      wltVersion   = toUnpack.get(UINT32)
      parent160    = toUnpack.get(BINARY_CHUNK, 20)
      serCryptInfo = toUnpack.get(VAR_STR)  # always 32B, not sure why VAR_STR
      serPayload   = toUnpack.get(VAR_STR)  
      rsecCode     = toUnpack.get(BINARY_CHUNK, 16)

      # Detect and correct any bad bytes in the data
      serPayload = Cpp.CheckRSErrorCorrect(serPayload, rsecCode)
      einfo = ArmoryCryptInfo().unserialize(serCryptInfo)

      if einfo.useEncryption():
         LOGERROR('Outer wallet entry encryption not yet implemented')
         we = WalletEntry(parentWlt, fileOffset, parent160, einfo, serPayload)
         we.isOpaque = True
         return we

         # At some point we'll support this properly
         #raise NotImplementedError('Outer encryption not avail in this version')
         #serPayload = einfo.decrypt(serPayload, **decryptKwargs)  

      # The following is all the data that is inside the payload, which is
      # all hidden/opaque if it's encrypted
      buPayload = BinaryUnpacker(serPayload)
      plType = buPayload.get(BINARY_CHUNK, 4)
      plReqd = buPayload.get(UINT8)
      plSize = buPayload.get(VAR_INT)
      plData = buPayload.getRemainingString()[:plSize]

      # This is the magic call:  create an object of the type referenced by
      # the 4-byte payload type, unserialize from the remaining data
      clsType = WalletEntry.FILECODEMAP.get(plType)
      if clsType is None:
         if plReqd > 0:
            LOGERROR('Unrecognized but critical data in wallet.  Disabling parent')
            self.wltFileRef.disableNode(parent160)
         else:
            LOGWARN('Unrecognized data type in wallet.  Ignoring')

      return plType]().unserialize(plData) 


   #############################################################################
   def serializeEntry(self, **encryptKwargs):

      # Going to create the sub-serialized object that might be encrypted
      serObject = self.serialize()
      lenObject = len(serObject )
      lenPadded = roundUpMod(lenPadded, self.defaultPad)
      paddedObj = padString(serObject, lenPadded)
      isReqd    = self.entryCode in WalletEntry.REQUIRED_TYPES

      payload = BinaryPacker() 
      bpPayload.put(BINARY_CHUNK, self.entryCode,   widthBytes=4) 
      bpPayload.put(UINT8,  1 if isReqd else 0)
      bpPayload.put(VAR_INT,  lenObject)
      bpPayload.put(BINARY_CHUNK, paddedObj)

      # Now we have the full unencrypted version of the data for the file
      serPayload = bpPayload.getBinaryString()
       
      if self.outerCryptInfo.useEncryption():
         raise NotImplementedError('Outer encryption not yet implemented!')
         serPayload = self.outerCryptInfo.encrypt(serPayload, **encryptKwargs)

      # Compute the 16-byte Reed-Solomon error-correction code
      rsecCode = Cpp.GenRSErrorCorrect(serPayload, 16)

      # Now we have everything we need to serialize the wallet entry
      bp = BinaryPacker()
      bp.put(UINT32,       getVersionInt(ARMORY_WALLET_VERSION)) 
      bp.put(BINARY_CHUNK, self.parent160,       widthBytes=20)
      bp.put(VAR_STR,      self.outerCryptInfo)
      bp.put(VAR_STR,      serPayload)
      bp.put(BINARY_CHUNK, rsecCode, widthBytes=16)
      return bp.getBinaryString()
      

   #############################################################################
   def getEkeyFromWallet(self, ekeyID):
      if self.wltFileRef is None:
         raise WalletExistsError('This wallet entry has not wallet file!')

      ekey = self.wltFileRef.ekeyMap.get(ekeyID)
      if ekey is None:
         raise KeyDataError('Encryption key does not exist in wallet file')

      return ekey



   #############################################################################
   def setPayloadPadding(self, padTo):
      if not padTo%16==0:
         LOGWARN('Padding should be set to a multiple of 16, to guarantee '
                 'compatibility with AES256')

      self.payloadPadding = padTo
   
   #############################################################################
   def getPayloadSize(self, padded=True):
      out = self.payloadSize
      if padded:
         out = roundUpMod(out, self.payloadPadding)
      return out


   #############################################################################
   def fsync(self):
      if self.wltFileRef is None:
         LOGERROR('Attempted to rewrite WE object but no wlt file ref.')

      if self.wltStartByte<=0:
         self.wltFileRef.doFileOperation('AddEntry', self)
      else:
         self.wltFileRef.doFileOperation('UpdateEntry', self)

   #############################################################################
   def isEncrypted(self):
      raise NotImplementedError


   #############################################################################
   def serializeWalletEntry(self):
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

      # This gets the derived class's serialize method and static entry code
      wePlain   = self.serialize()
      weCode    = self.entryCode

      weBytes   = lenBytes(wePlain) 

      # Decide whether to write encrypted data
      if self.outerCryptInfo.useEncryption():
         wePlain = self.payloadCrypt
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

      weChk = getRSErrorCorrect(weData)

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
      bp.put(BINARY_CHUNK, self.outerCryptInfo.serialize(),     widthBytes=32)

      # Put in checksum of header data
      weHeadChk = computeChecksum(bp.getBinaryString())
      bp.put(BINARY_CHUNK, weHeadChk,                        widthBytes= 4)

      # Write the serialized data and its checksum
      bp.put(BINARY_CHUNK, weData)                          #width=weData+Padding
      bp.put(BINARY_CHUNK, weChk,                            widthBytes= 4)

      return bp.getBinaryString()


   #############################################################################
   def unserializeWalletEntry(self, toUnpack, fileOffset=None)
      """
      We will always be reading WalletEntry objs from a single BinaryUnpacker
      object which unpacks the entire file contiguously.  Therefore, the 
      getPosition call will return the same value as the starting byte in
      the file
      """
      if isinstance(toUnpack, BinaryUnpacker):
         binUnpacker = toUnpack
         if fileOffset is None:
            fileOffset = binUnpacker.getPosition()
      else:
         binUnpacker = BinaryUnpacker(toUnpack)
         if fileOffset is None:
            fileOffset=-1

      weHead    = binUnpacker.get(BINARY_CHUNK, 4+4+4+4+20+32)
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
      weCrypto = headUnpacker.get(BINARY_CHUNK, 32)

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

      if not self.outerCryptInfo.noEncryption():
         # Encrypted data is stored as raw binary string.  
         self.payloadPlain   = ''
         self.payloadCrypt = weData
      else:
         # Unencrypted data is immediately unserialized into the appropriate obj
         payloadClass   = self.FILECODEMAP[weCode]
         self.payloadPlain   = payloadClass().unserialize(weData[:weBytes])
         self.payloadCrypt = ''
         self.payloadPlain.wltEntryRef = self


      self.parentRoot160 = weRoot
      self.wltStartByte = fileOffset
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
      is needed, and how to get it.  Check the self.outerCryptInfo

      WalletEntry encryption is the "outer" encryption, of the entire WE 
      object.  If the data itself has encryption (inner encryption, such
      as for private key data in an ArmoryAddress object), that is irrelevant
      to this method
      """

      if not self.outerCryptInfo.useEncryption():
         LOGWARN('Trying to lock unencrypted data...?')
         return

      # Check for the very simple locking case:
      if len(self.payloadCrypt) > 0:
         if encryptKey is None:
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
      plain = addPadding(plain, self.outerCryptInfo.getBlockSize())
      self.payloadCrypt = self.outerCryptInfo.encrypt(plain, encryptKey, encryptIV)
      self.payloadPlain = None
      return

   #############################################################################
   def unlock(self, encryptKey, encryptIV=None):
      """ 
      It's up to the caller to check beforehand if an encryption key or IV
      is needed, and how to get it.  Check the self.outerCryptInfo

      WalletEntry encryption is the "outer" encryption, of the entire WE 
      object.  If the data itself has encryption (inner encryption, such
      as for private key data in an ArmoryAddress object), that is irrelevant
      to this method
      """
      if not self.outerCryptInfo.useEncryption():
         LOGWARN('Trying to unlock unencrypted data...?')
         return

        
      if not self.payloadPlain is None:
         # Already unlocked
         return

      if self.payloadCrypt is None:
         LOGERROR('No payload to decrypt')
         return 
         

      plain = self.outerCryptInfo.decrypt(self.payloadCrypt, encryptKey, encryptIV)
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
                 #self.wltStartByte, \
                 #binary_to_hex(self.parentRoot160[:4]), \

      #self.entryCode       = weCode

      #self.wltFileRef      = wltFileRef
      #self.wltStartByte      = wltByteLoc

      #self.parentRoot160   = parentRoot
      #self.outerCryptInfo     = encr
      #self.initPayload(payload, payloadSize, encr)

      # Default to padding all data in file to modulo 16 (helps with crypto)
      #self.setPayloadPadding(16)

      #self.lockTimeout  = 10   # seconds after unlock, that key is discarded
      #self.relockAtTime = 0    # seconds after unlock, that key is discarded



   #############################################################################
   @staticmethod
   def deleteThisEntry(self, doFsync=True):
      """ 
      Static method for creating deleted wallet-entry objects.  DeleteData can
      either be a number (the number of zero bytes to write, or it can be an
      existing WalletEntry object, where we will simply figure out how big the
      payload is and create a new object with the same number of zero bytes.
      """

      nBytes = self.getPayloadSize(padded=True)
      self.entryCode = 'ZERO'
      self.outerCryptInfo = ArmoryCryptInfo(None)
      self.payloadPlain = ZeroData(nBytes)
      self.payloadCrypt = None
      self.payloadSize = nBytes
      self.payloadPadding = 0

      if not self.wltFileRef is None and self.wltStartByte>0 and doFsync:
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

      # Any lockboxes that are maintained in this wallet file
      # Indexed by p2sh-scrAddr
      self.lockboxMap = {}

      # List of all master encryption keys in this wallet (and also the 
      # data needed to understand how to decrypt them, probably by KDF)
      self.ekeyMap = {}

      # List of all KDF objects -- probably created based on testing the 
      # system speed when the wallet was created
      self.kdfMap  = {}

      # Master address list of all wallets/roots/chains that could receive BTC
      self.masterAddrMap  = {}

      # List of all encrypted wallet entries that couldn't be decrypted 
      # Perhaps later find a way decrypt and put them into the other maps
      self.opaqueList  = []

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
                                maxMem=32*MEGABYTE,
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
         oldData = self.readWalletEntry(theData.wltStartByte).serialize()
         if len(newData)==len(oldData):
            fileLoc = theData.wltStartByte
            operationType = 'Modify'
         else:
            LOGINFO('WalletEntry replace != size (%s).  ', theData.entryCode)
            LOGINFO('Delete&Append')
            self.addFileOperationToQueue('DeleteEntry', theData.wltStartByte)
            operationType = 'Append'
      elif operationType.lower()=='deleteentry':
         # Delete an entry from the wallet
         fileLoc = theData.wltStartByte if isWltEntryObj else theData
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
            theData.wltStartByte = -1

      else:
         if not isinstance(theData, basestring):
            LOGERROR('Can only add/update wallet data with string or unicode type!')
            return

         newData = theData[:]

      #####
      # This is where it actually gets added to the queue.
      if operationType.lower()=='append':
         if isWltEntryObj:
            theData.wltStartByte =  self.lastFilesize
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
      if not securePassphrase is None:
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
         (1) KDF algorithm & params   (via ID)  (8)
         (2) Encryption algo & params (via ID)  (8)
         (3) Encryption key source              (8)
         (4) Initialization Vect source         (8)

   The examples below use the following IDs, though they would normally be
   hash of the parameters used:

         KDF object with ID      '11112222aaaabbbb'   hash(ROMixOver2 w/ params)
         Crypto obj with ID      'ccccdddd88889999'   hash(AES256-CFB generic)
         Master key ID           '9999999932323232'   hash(WalletEntry object)


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
   def __init__(self, kdfAlgo=NULLSTR(8), \
                      encrAlgo=NULLSTR(8), \
                      keysrc=NULLSTR(8), \
                      ivsrc=NULLSTR(8)):

      if kdfAlgo is None:
         kdfAlgo = NULLSTR(8)

      # Now perform the encryption using the encryption key
      if (not kdfAlgo==NULLSTR(8)) and (not KdfObject.kdfIsRegistered(kdfAlgo)):
         raise UnrecognizedCrypto('Unknown KDF algo: %s', kdfAlgo)

      # Now perform the encryption using the encryption key
      if not (encrAlgo==NULLSTR(8)) and (not encrAlgo in KNOWN_CRYPTO):
         raise UnrecognizedCrypto('Unknown encryption algo: %s', encrAlgo)

      self.kdfObjID     = kdfAlgo
      self.encryptAlgo  = encrAlgo
      self.keySource    = keysrc
      self.ivSource     = ivsrc

      # Use this to hold temporary key data when using chained encryption
      self.tempKeyDecrypt = SecureBinaryData(0)


   ############################################################################
   def noEncryption(self):
      return (self.kdfObjID==NULLSTR(8) and \
              self.encryptAlgo==NULLSTR(8) and \
              self.keySource==NULLSTR(8) and \
              self.ivSource==NULLSTR(8))

   #############################################################################
   def useEncryption(self):
      return (not self.encryptInfo.noEncryption())

   ############################################################################
   def useKeyDerivFunc(self):
      return (not self.kdf==NULLSTR(8))

   ############################################################################
   def copy(self):
      return ArmoryCryptInfo().unserialize(self.serialize())

   ############################################################################
   def hasStoredIV(self):
      if self.ivSource==NULLSTR(8):
         LOGWARNING('hasStoredIV() called on object with ID_ZERO.  All ')
         LOGWARNING('encryption objects should have a stored IV, or sentinel')
         return False

      # A non-zero ivSource is "stored" if it's not one of the sentinel values
      return (self.getEncryptIV()[0] == CRYPT_IV_SRC.STOREDIV)


   ############################################################################
   def setIV(self, newIV):
      if not self.ivSource is NULLSTR(8):
         LOGWARNING('Setting IV on einfo object with non-zero IV')
      
      if not isinstance(newIV, str):
         newIV = newIV.toBinStr()

      if len(newIV)>8:
         LOGWARNING('Supplied IV is not 8 bytes. Truncating.')
      elif len(newIV)<8:
         raise BadInputError('Supplied IV is less than 8 bytes.  Aborting')

      self.ivSource = newIV

   ############################################################################
   def getEncryptKeySrc(self):
      
      if self.keySource in ['PARCHAIN', 'PASSWORD', 'MULTIPWD']:
         enumOut = getattr(CRYPT_KEY_SRC, self.keySource)
         return (enumOut, '')
      else:
         return (CRYPT_KEY_SRC.EKEY_OBJ, self.keySource)



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
      # expected size.  Only if there is no KDF but does have encryptAlgo, then 
      # we return the key size of that algo.
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


   ############################################################################
   def unserialize(self, theStr):
      bu = makeBinaryUnpacker(toUnpack)
      self.kdfObjID    = bu.get(BINARY_CHUNK, 8)
      self.encryptAlgo = bu.get(BINARY_CHUNK, 8)
      self.keySource   = bu.get(BINARY_CHUNK, 8)
      self.ivSource    = bu.get(BINARY_CHUNK, 8)
      return self
       
   ############################################################################
   def copy(self):
      return ArmoryCryptInfo().unserialize(self.serialize())

   ############################################################################
   @VerifyArgTypes(keyData=SecureBinaryData,  
                   ivData=SecureBinaryData)
   def prepareKeyDataAndIV(self, keyData=None, ivData=None, ekeyObj=None):
      """
      This is the code that is common to both the encrypt and decrypt functions.
      """

      # IV data might actually be part of this object, not supplied
      if not self.hasStoredIV():
         if ivData.getSize()==0:
            LOGERROR('Cannot [en|de]crypt without initialization vector.')
            raise InitVectError 
         ivData = SecureBinaryData(ivData)
      elif ivData.getSize()==0:
         ivData = self.ivSource.copy()
      else:
         LOGERROR('ArmoryCryptInfo has stored IV and was also supplied one!')
         LOGERROR('Do not want to risk encrypting with wrong IV ... bailing')
         raise InitVectError 

      # All IV data is 8 bytes, though it needs to be the blocksize of the
      # cipher.  It has enough entropy, just not big enough.
      ivData = stretchIV(ivData, self.getBlockSize())


      # When we have an ekeyObj, it means we should apply the supplied 
      # passphrase/keyData to it to decrypt the master key (not this obj).
      # Then overwrite keyData with the decrypted masterkey since that is
      # the correct key to decrypt this object.
      if ekeyObj is None:
         keysrc = self.getEncryptKeySrc()[0]
         if keysrc == CRYPT_KEY_SRC.EKEY_OBJ:
            raise EncryptionError('EncryptionKey object required but not supplied')
      else:
         # We have supplied a master key to help encrypt this object
         if self.useKeyDerivFunc():
            raise EncryptionError('Master key encryption should never use a KDF')

         # If supplied master key is correct, its ID should match stored value
         if not ekeyObj.getEncryptionKeyID() == self.keySource:
            LOGERROR
            raise EncryptionError('Supplied ekeyObj does not match keySource')

         # Make sure master key is unlocked -- use keyData arg if locked
         if ekeyObj.isLocked():         
            if keyData is None:
               raise EncryptionError('Supplied locked ekeyObj w/o passphrase')

            # Use the supplied keydata to unlock the *MASTER KEY*
            # Note "unlock" will call the ekeyObj.einfo.decrypt
            if not ekeyObj.unlock(keyData):
               raise EncryptionError('Supplied locked ekeyObj bad passphrase')

         # Store tempKeyDecrypt in self so we can destroy it outside this func
         self.tempKeyDecrypt = ekeyObj.masterKeyPlain.copy()
         keyData = self.tempKeyDecrypt
         ekeyObj.lock()
      
         
      # Apply KDF if it's requested
      if self.useKeyDerivFunc(): 
         if not KdfObject.kdfIsRegistered(self.kdfObjID):
            kdfIDHex = binary_to_hex(self.kdfObjID)
            raise KdfError('KDF is not registered: %s' % kdfIDHex)
                                            
         keyData = KdfObject.REGISTERED_KDFS[self.kdfObjID].execKDF(keyData)
   
      # Check that after all the above, our final keydata is the right size 
      expectedSize = KNOWN_CRYPTO[self.encryptAlgo]['keysize']
      if not keyData.getSize()==expectSize:
         raise EncryptionError('Key is wrong size! Key=%d, Expect=%s' % \
                                            (keyData.getSize(), expectedSize)

      return keyData, ivData


   ############################################################################
   @VerifyArgTypes(plaintext=SecureBinaryData, 
                   keyData=SecureBinaryData,  
                   ivData=SecureBinaryData)
   def encrypt(self, plaintext, keyData=None, ivData=None, ekeyObj=None):
      """
      Ways this function is used:

         -- We are encrypting the data with a KDF & passphrase only:
               ekeyObj == None
               keyData is the passphrase (will pass through the KDF)
               ivData contains the IV to use for encryption of this object

         -- We are encrypting with a raw AES256 key
               ekeyObj == None
               keyData is the raw AES key (KDF is ignored/should be NULL)
               ivData contains the IV to use for encryption of this object

         -- We are encrypting using a master key 
               ekeyObj == MasterKeyObj
               keyData is the passphrase for the *MASTER KEY*
               ivData contains the IV to use for encryption of this object
               (the master key carries its own IV, no need to pass it in)

      If using a master key, we are "chaining" the encryption.  Normally we
      have an encrypted object, take a passphrase, pass it through the KDF,
      use it to decrypt our object.  

      When using a master key, the above process is applied to the encrypted
      master key, which will give us the encryption key to decrypt this 
      object.  

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

      # Verify that the plaintext data has correct padding
      if not (plaintext.getSize() % self.getBlockSize() == 0):
         LOGERROR('Plaintext has wrong length: %d bytes', plaintext.getSize())
         LOGERROR('Length expected to be padded to %d bytes', self.getBlockSize())
         raise EncryptionError('Cannot encrypt non-multiple of blocksize')

      try:
         useKey,useIV = self.prepareKeyDataAndIV(ekeyObj, keyData, ivData)
   
         # Now perform the encryption using the encryption key
         if self.encryptAlgo=='AE256CFB':
            return CryptoAES().EncryptCFB(plaintext, useKey, useIV)
         elif self.encryptAlgo=='AE256CBC':
            return CryptoAES().EncryptCBC(plaintext, useKey, useIV)
         else:
            raise UnrecognizedCrypto('Unknown algo: %s' % self.encryptAlgo)
            
      finally:
         # If chained encryption, tempKeyDecrypt has the decrypted master key
         self.tempKeyDecrypt.destroy()



   ############################################################################
   @VerifyArgTypes(ciphertext=SecureBinaryData, 
                   keyData=SecureBinaryData,  
                   ivData=SecureBinaryData)
   def decrypt(self, ciphertext, keyData=None, ivData=None, ekeyObj=None):
      """
      See comments for encrypt function -- this function works the same way
      """

      # Make sure all the data is in SBD form -- will also be easier to destroy
      if not (ciphertext.getSize() % self.getBlockSize() == 0):
         LOGERROR('Ciphertext has wrong length: %d bytes', ciphertext.getSize())
         LOGERROR('Length expected to be padded to %d bytes', self.getBlockSize())
         raise EncryptionError('Cannot decrypt non-multiple of blocksize')

      try:
         useKey,useIV = self.prepareKeyDataAndIV(ekeyObj, keyData, ivData)

         # Now perform the decryption using the key
         if self.encryptAlgo=='AE256CFB':
            return plain = CryptoAES().DecryptCFB(ciphertext, useKey, ivData)
         elif self.encryptAlgo=='AE256CBC':
            return plain = CryptoAES().DecryptCBC(ciphertext, useKey, ivData)
         else:
            raise UnrecognizedCrypto('Unrecognized algo: %s' % self.encryptAlgo)
         
      finally:
         # If chained encryption, tempKeyDecrypt has the decrypted master key
         self.tempKeyDecrypt.destroy()




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
                      'scrypt__': ['n','r','i'] } # not actually avail yet
   REGISTERED_KDFS = { }

   #############################################################################
   def __init__(self, kdfName=None, **params):

      # Set an error-inducing function as the default KDF
      def errorkdf(x):
         LOGERROR('Using uninitialized KDF!')
         return SecureBinaryData(0)
      self.execKDF = errorkdf


      if kdfName is None:
         # Stay uninitialized
         self.kdfName = ''
         self.kdf = None
         return
         

      if not kdfName.lower() in self.KDF_ALGORITHMS:
         # Make sure we recognize the algo
         LOGERROR('Attempted to create unknown KDF object:  name=%s', kdfName)
         return

      # Check that the keyword args passed to this function includes all 
      # required args for the specified KDF algorithm 
      reqdArgs = self.KDF_ALGORITHMS[kdfName.lower()]
      for arg in reqdArgs:
         if not arg in params:
            LOGERROR('KDF name=%s:   not enough input arguments', kdfName)
            LOGERROR('Required args: %s', ''.join(reqdArgs))
            return
            

      # Right now there is only one algo (plus identity-KDF).  You can add new
      # algorithms via "KDF_ALGORITHMS" and then updating this method to 
      # create a callable KDF object
      if kdfName.lower()=='identity':
         self.execKDF = lambda x: SecureBinaryData(x)
      if kdfName.lower()=='romixov2':

         memReqd = params['memReqd']
         numIter = params['numIter']
         salt    = params['salt'   ]

         # Make sure that non-SBD input is converted to SBD
         saltSBD = SecureBinaryData(salt)

         if memReqd>2**31:
            raise KdfError('Invalid memory for KDF.  Must be 2GB or less.')
         

         if saltSBD.getSize()==0:
            raise KdfError('Zero-length salt supplied with KDF')
            
         self.kdfName = 'ROMixOv2'
         self.memReqd = memReqd
         self.numIter = numIter
         self.salt    = saltSBD
         self.kdf = KdfRomix(self.memReqd, self.numIter, self.salt) 
         self.execKDF = lambda pwd: self.kdf.DeriveKey( SecureBinaryData(pwd) )

      else:
         raise KdfError('Unrecognized KDF name')


   #############################################################################
   def getKdfID(self):
      return computeChecksum(self.serialize(), 8)
      
   ############################################################################
   @staticmethod
   def RegisterKDF(kdfObj):
      LOGINFO('Registering KDF object: %s', binary_to_hex(kdfObj.getKdfID()))
      KdfObject.REGISTERED_KDFS[kdfObj.getKdfID()] = kdfObj

   ############################################################################
   @staticmethod
   def kdfIsRegistered(kdfObjID):
      return KdfObject.REGISTERED_KDFS.has_key(kdfObjID)

   ############################################################################
   @staticmethod
   def getRegisteredKDF(kdfID):
      if not KdfObject.kdfIsRegistered(kdfID):
         raise UnrecognizedCrypto('Unregistered KDF: %s', binary_to_hex(kdfID))
      return KdfObject.REGISTERED_KDFS[kdfID] 

   #############################################################################
   def serialize(self):
      bp = BinaryPacker()
      if self.kdfName.lower()=='romixov2':
         bp.put(BINARY_CHUNK,  self.kdfname,           widthBytes= 8)
         bp.put(BINARY_CHUNK,  'sha512',               widthBytes= 8)
         bp.put(UINT32,        self.memReqd)          #widthBytes= 4
         bp.put(UINT32,        self.numIter)          #widthBytes= 4
         bp.put(VAR_STR,       self.salt.toBinStr())
      elif self.kdfName.lower()=='identity':
         bp.put(BINARY_CHUNK,  'Identity',             widthBytes= 8)

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
            raise KdfError('ROMixOv2 KDF only works with sha512: found %s', useHash)

         mem   = bu.get(UINT32)
         nIter = bu.get(UINT32)
         salty = bu.get(VAR_STR)
         self.__init__(kdfName, memReqd=mem, numIter=nIter, salt=salty)

      return self



   #############################################################################
   def createNewKDF(self, kdfName, targSec=0.25, maxMem=32*MEGABYTE, 
                                                           doRegisterKDF=True):
      
      LOGINFO("Creating new KDF object")

      if not (0 <= targSec <= 20):
         raise KdfError('Must use positive time < 20 sec.  Use 0 for min settings')

      if not (32*KILOBYTE <= maxMem < 2*GIGABYTE):
         raise KdfError('Must use maximum memory between 32 kB and 2048 MB')

      if not kdfName.lower() in self.KDF_ALGORITHMS:
         raise KdfError('Unknown KDF name in createNewKDF:  %s' % kdfName)
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
         LOGINFO('\t  MemReqd: %0.2f MB' % (float(mem)/MEGABYTE))
         LOGINFO('\t  NumIter: %d', nIter)
         LOGINFO('\t  HexSalt: %s', self.kdf.getSalt().toHexStr())

      if doRegisterKDF:
         KdfObject.RegisterKDF(self)

      return self



#############################################################################
#############################################################################
class EncryptionKey(object):
   """
   This is a simple container to hold a 32-byte master encryption key.  
   Typically this key will be used to encrypt everything else in the wallet.
   Locking, unlocking, and changing the passphrase will only require operating
   on this master key (for instance, rather than changing the encryption of 
   every object in the wallet, we keep it the same, but re-encrypt this master
   key).

   Also includes an optional test string, which can be encrypted at creation
   time to distribute if the passphrase is forgotten, and you want to hire
   computing power to help you recover it.
   """

   REGISTERED_EKEYS = { }

   #############################################################################
   def __init__(self, keyID=None, ckey=None, einfo=None, 
                                    etest=None, ptest=None, keyH3=None):
      # Mostly these will be initialized from encrypted data in wallet file
      self.ekeyID           = keyID   if keyID   else NULLSBD()
      self.masterKeyCrypt   = SecureBinaryData(ckey)  if ckey  else NULLSBD()
      self.testStringEncr   = SecureBinaryData(etest) if etest else NULLSBD()
      self.testStringPlain  = SecureBinaryData(ptest) if ptest else NULLSBD()
      self.keyTripleHash    = SecureBinaryData(keyH3) if keyH3 else NULLSBD()

      self.keyCryptInfo = ArmoryCryptInfo(None)
      if einfo:
         self.keyCryptInfo = einfo.copy()

      # We may cache the decrypted key      
      self.masterKeyPlain      = NULLSBD()
      self.relockAtTime        = 0
      self.lockTimeout         = 10


   
   #############################################################################
   def getEncryptionKeyID(self):
      if self.ekeyID is None:
         if self.isLocked():
            raise EncryptionError('No stored ekey ID, and ekey is locked')

         self.ekeyID = calcEKeyID(self.masterKeyPlain)
      return self.ekeyID

   #############################################################################
   @VerifyArgTypes(passphrase=SecureBinaryData)
   def verifyPassphrase(self, passphrase):
      return self.unlock(passphrase, justVerify=True)


   #############################################################################
   @VerifyArgTypes(passphrase=SecureBinaryData)
   def unlock(self, passphrase, justVerify=False):
      LOGDEBUG('Unlocking encryption key %s', self.ekeyID)
      self.masterKeyPlain = \
               self.keyCryptInfo.decrypt(self.masterKeyCrypt, passphrase)

      if not calcEKeyID(self.masterKeyPlain)==self.ekeyID:
         LOGERROR('Wrong passphrase passed to EKEY unlock function.')
         self.masterKeyPlain.destroy()
         return False
   
      if justVerify:
         self.masterKeyPlain.destroy()
      else:
         self.relockAtTime = RightNow() + self.lockTimeout

      return True



   #############################################################################
   @VerifyArgTypes(passphrase=[SecureBinaryData, None])
   def lock(self, passphrase=None):
      LOGDEBUG('Locking encryption key %s', self.ekeyID)
      try:
         if self.masterKeyCrypt.getSize()==0:
            if passphrase is None:
               LOGERROR('No encrypted master key, and no passphrase for lock()')
               LOGERROR('Deleting it anyway.')
               return False
            else:
               passphrase = SecureBinaryData(passphrase)
               self.masterKeyCrypt = self.keyCryptInfo.encrypt( \
                                                   self.masterKeyPlain, 
                                                   passphrase)
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
      bp.put(BINARY_CHUNK, self.ekeyID, widthBytes=8)
      bp.put(VAR_STR,      self.masterKeyCrypt)
      bp.put(VAR_STR,      self.keyCryptInfo.serialize())
      bp.put(VAR_STR,      self.testStringEncr.toBinStr())
      bp.put(VAR_STR,      self.testStringPlain.toBinStr())
      bp.put(VAR_STR,      self.keyTripleHash.toBinStr())
      return bp.getBinaryString()


   #############################################################################
   def unserialize(self, strData):
      bu = makeBinaryUnpacker(strData)
      ekeyID   = bu.get(BINARY_CHUNK,  8)
      cryptKey = bu.get(VAR_STR)
      einfoStr = bu.get(VAR_STR)
      eteststr = bu.get(VAR_STR)
      pteststr = bu.get(VAR_STR)
      keyHash3 = bu.get(VAR_STR)

      einfo = ArmoryCryptInfo().unserialize(einfoStr)

      self.__init__(ekeyID, cryptKey, einfo, teststr, pteststr, keyHash3)
      return self


   #############################################################################
   @VerifyArgTypes(passphrase=SecureBinaryData,
                   preGenKey=[SecureBinaryData, None])
   def CreateNewMasterKey(self, encryptEkeyKdfID, encryptEkeyAlgo, passphrase,
                                withTestString=False, preGenKey=None):
      """
      This method assumes you already have a KDF you want to use and is 
      referenced by the first arg.  If not, please create the KDF and
      add it to the wallet first (and register it with KdfObject class)
      before using this method.

      Generally, ArmoryCryptInfo objects can have a null KDF, but master
      encryption keys are almost always protected by a passphrase so it 
      will use a KDF.

      You can provide pre-generated key and IV, if you are simply trying
      to update the password or KDF options on an existing key
      """

      LOGINFO('Generating new master key')

      # Check for the existence of the specified KDF      
      if not KdfObject.kdfIsRegistered(encryptEkeyKdfID):
         LOGERROR('Cannot create new master key without KDF.  Use') 
         LOGERROR('KdfObject().createNewKDF("ROMixOv2", targSec=X, maxMem=Y)')
         raise KdfError('Unregistered KDF: %s' % encryptEkeyKdfID)


      # Check that we recognize the encryption algorithm
      # This is the algorithm used to encrypt the master key itself
      if not encryptEkeyAlgo in KNOWN_CRYPTO:
         raise UnrecognizedCrypto('Unknown encrypt algo: %s' % encryptEkeyAlgo)

         
      # Generate the IV to be used for encrypting the master key with pwd
      newIV = SecureBinaryData().GenerateRandom(8).toBinStr()

      # Create the object that explains how this master key will be encrypted
      self.keyCryptInfo = ArmoryCryptInfo(encryptEkeyKdfID, encryptEKeyAlgo, 
                                                             'PASSWORD', newIV)

      # Create the master key itself
      if preGenKey:
         newMaster = preGenKey.copy()
      else:
         newMaster = SecureBinaryData().GenerateRandom(32)

      self.ekeyID = calcEKeyID(newMaster)
      self.masterKeyCrypt = self.keyCryptInfo.encrypt(newMaster, passphrase)

      # We might have decided to encrypt a test string with this key, so that
      # later if the user forgets their password they can distribute just the
      # test string to be brute-force decrypted (instead of their full wallet)
      if not withTestString:
         self.testStringPlain = NULLSTR(0)
         self.testStringEncr  = NULLSTR(0)
         self.keyTripleHash   = NULLSTR(0)
      else:
         # Note1: We are using the ID of the encryption key as the IV for
         #        the test string (it will be expanded by the encrypt func)
         # Note2: We use the encrypted test string essentially as a unique 
         #        salt for this wallet for the triple-hashed key.  
         #        It seems unnecessary since the master key should be a 
         #        true 32-bytes random (how would it not be?) but it doesn't 
         #        hurt either.  If/when we put out a bounty/reward script,
         #        the claimant will have to put (masterKey||testStrEncr) 
         #        onto the stack, which will be hashed three times and 
         #        compared against self.keyTripleHash.
         minfo = ArmoryCryptInfo(NULLKDF, encryptEKeyAlgo, 'RAW_EKEY', self.ekeyID)
         rand16 = SecureBinaryData().GenerateRandom(16)
         self.testStringPlain = SecureBinaryData('ARMORYENCRYPTION') + rand16
         self.testStringEncr  = minfo.encrypt(self.testStringPlain, newMaster)
         self.keyTripleHash   = hash160(hash256(hash256(newMaster.toBinStr() + \
                                                        self.testStringEncr)))

      # We should have an encrypted version now, so we can wipe the plaintext
      newMaster.destroy()

      LOGINFO('Finished creating new master key:')
      LOGINFO('\tKDF:     %s', binary_to_hex(kdfID))
      LOGINFO('\tCrypto:  %s', encryptEKeyAlgo)
      LOGINFO('\tTestStr: %s', binary_to_hex(self.testStringPlain[16:]))

      return self



   #############################################################################
   @VerifyArgTypes(oldPass=SecureBinaryData,
                   newPass=SecureBinaryData)
   def changePassphraseAndOrKDF(self, oldPass, newPass, 
                                 newKdfID=None, newEncryptAlgo=None):
      """
      Pass in the same object for old and new if you want to keep the same
      passphrase but change the KDF
      """
      if not self.unlock(oldPass):
         raise PassphraseError('Wrong passphrase given')

      if newKdfID is None:
         newKdfID = self.keyCryptInfo.kdfObjID

      if newEncryptAlgo is None:
         newEncryptAlgo = self.keyCryptInfo.encryptAlgo

      withTest = (self.testStringEncr != NULLSTR(32))
         
      # Not creating a new key, but the process is the same; use preGenKey arg
      self.CreateNewMasterKey(newKdfID,
                              newEncryptAlgo,
                              newPass,
                              withTest, 
                              preGenKey=self.masterKeyPlain)

      self.lock(newPass)
                              


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

      kdfid  = self.keyCryptInfo.kdfObjID
      kdfObj = KdfObject.getRegisteredKDF(kdfid)

      if not kdfObj.kdfName.lower()=='romixov2':
         raise UnrecognizedCrypto('Unknown KDF')

      encryptAlgo = self.keyCryptInfo.encryptAlgo
      kdfName   = kdfObj.kdfName
      memReqd   = kdfObj.memReqd
      numIter   = kdfObj.numIter
      kdfSalt1  = kdfObj.salt.toHexStr()[:32 ]
      kdfSalt2  = kdfObj.salt.toHexStr()[ 32:]
      cryptKey1 = self.masterKeyCrypt.toHexStr()[:32 ]
      cryptKey2 = self.masterKeyCrypt.toHexStr()[ 32:]
      testStr1  = binary_to_hex(self.testStringEncr)[:32 ]
      testStr2  = binary_to_hex(self.testStringEncr)[ 32:]

      hintBlock = textwrap.wrapText(' '.join(userhints))

      challengeText = """
      ------------------------------------------------------------
      Armory Passphrase Recovery Challenge
      ------------------------------------------------------------

      The master key is encrypted in the following way:
            Encryption:      %(encryptAlgo)s
            KDF Algorithm:   %(kdfName)s
            KDF Mem Used:    %(memReqd)s
            KDF NumIter:     %(numIter)s
      
            KDF Salt (32B):  %(kdfSalt1)s
                             %(kdfSalt2)s
     
            Encrypted Key:   %(cryptKey1)s
                             %(cryptKey2)s

      The test string is 32 bytes, encrypted with the above key:
         Encrypted Str:      %(testStr1)s
                             %(testStr2)s
      
      The decrypted test string starts with the following:
         First16 (ASCII): ARMORYENCRYPTION
         First16 (HEX):   41524d4f5259454e4352595054494f4e

      Once you have found the correct passphrase, you can 
      use the second 16 bytes as proof that you have succeeded. 
      Use the entire decrypted string as the secret key to 
      send a message authentication code to the user with 
      your email address and bounty-payment address (and any
      other relevant information).
      
      The message authentication code is computed like this: 
         mac = toHex(HMAC_SHA256(decrypted32, msg))
     
      ------------------------------------------------------------
      The following information is supplied by the user to 
      help you find the passphrase and submit your proof: 

         User email:  %(useremail)s
         User hints: 
            %(hintBlock)s
      ------------------------------------------------------------
      """) % locals()

      return challengeText
      

   #############################################################################
   def testKeyRecoveryMAC(self, userstr, responseMacHex):
      LOGINFO('Testing key recovery MAC:')

      LOGINFO('   User Info :     %s', userstr)
      userstr = SecureBinaryData(userstr)
      hmac = HDWalletCrypto().HMAC_SHA256(self.testStringPlain, userstr)

      LOGINFO('   MAC (given):    %s', responseMacHex)
      LOGINFO('   MAC (correct):  %s', hmac.toHexStr())
      return (hmac.toHexStr()==responseMacHex)

   
   #############################################################################
   def createBountyRewardScript(self, claimAddrStr):
      """
      This is based on what I posted on bitcointalk.org a while back (that I 
      can't seem to find again).  The idea is that we have the 
      hash^3(masterKey) stored in the wallet file, so we can create a
      tx script that requires both a signature, and the disclosure of a
      piece of data that hashes to self.keyTripleHash.  
      
      To avoid people hijacking the bounty-claimed transaction, we don't post
      a naked bounty from the start (requiring only the key to be disclosed).
      Instead, we wait for the brute-forcer to prove they have found the key
      and send us an HMAC with their bounty reward address using the decrypted
      test string.  Once we have their payment address, we send coins to a
      script that requires BOTH:  a signature from that address AND the 32
      bytes that hashes to self.keyTripleHash
      """
      NotImplementedError('Not sure if we will ever implement this...')

      if not addrStr_to_hash160(claimAddrStr)[0] == ADDRBYTE:
         raise BadInputError('Can only use regular P2PKH for claim scripts')


         
################################################################################
################################################################################
class MultiPwdEncryptionKey(object):
   """
   So there is a master encryption key for your wallet.
   The key itself is never stored anywhere, only the M-of-N fragments of it.
   The fragments are stored on disk, each encrypted with a different password.
   
   So instead of:

      ekeyInfo | encryptedMasterKey

   we will have:

      ekeyInfo0 | keyFrag0 | ekeyInfo1 | keyFrag1 | ... 


   We intentionally do not have a way to verify if an individual password
   is correct without having a quorum of correct passwords.  This makes
   sure that master key is effectively encrypted with the entropy of 
   M passwords, instead of M keys each encrypted with the entropy of one
   password (reduced ever-so-slightly if M != N)

   """

   #############################################################################
   def __init__(self, keyID=None, M=None, einfoFrags=None, efragList=None, 
                                                         keyLabelList=None):
      """
      einfoMaster is the encryption used to encrypt the master key (raw AES key)
      einfoList is the encryption used for each fragment (password w/ KDF)

      When this method is called with args, usually after reading the encrypted
      data from file.
      """
      self.ekeyID      = keyID  if keyID  else NULLSTR(0)
      self.M           = M if M else 0
      self.N           = len(einfoFrags) if einfoFrags else 0

      if efragList and not isinstance(efragList, (list,tuple,NoneType)):
         raise BadInputError('Need list of einfo & SBD objs for frag list')
      
      # This contains the encryption/decryption params for each key frag
      self.einfos = []
      if einfoList:
         self.einfos = [e.copy() for e in einfoList]

      # The actual encryption fragments
      self.efrags = []
      if efragList:
         self.efrags = [SecureBinaryData(f) for f in efragList]

      # The actual encryption fragments
      self.labels = []
      if keyLabelList:
         self.labels = keyLabelList[:]


      # If the object is unlocked, we'll store a the plain master key here
      self.masterKeyPlain      = SecureBinaryData(0)
      self.relockAtTime        = 0
      self.lockTimeout         = 10




   #############################################################################
   def getEncryptionKeyID(self):
      if self.ekeyID is None:
         # Needs to be computed
         if self.isLocked():
            raise EncryptionError('No stored ekey ID, and ekey is locked')
         self.ekeyID = calcEKeyID(self.masterKeyPlain)
      return self.ekeyID


   #############################################################################
   def verifyPassphraseList(self, sbdPasswdList):
      return self.unlock(sbdPasswdList, justVerify=True)

   #############################################################################
   def unlock(self, sbdPasswdList, justVerify=False):
      LOGDEBUG('Unlocking multi-encrypt key %s', self.ekeyID)

      if self.M==0 or self.N==0:
         raise BadInputError('Multi-encrypt master key not initialized')
      

      npwd = sum([(1 if p.getSize()>0 else 0) for p in sbdPasswdList]) 
      if npwd < self.N:
         raise BadInputError('Only %d pwds, %d needed' % (npwd, self.N))
                                                   
      # pfrags will contain the (x,y) pairs (fragments) 
      pfrags = []
      for i,pwd in enumerate(sbdPasswdList):
         if pwd.getSize()==0:
            continue

         # The einfo object carries all the KDF and IV info with it
         pfrags.append([int_to_binary(i, BIGENDIAN), 
                        self.einfos[i].decrypt(self.efrags[i], pwd).toBinStr()])
          
      try:
         # Reconstruct the master encryption key from the decrypted fragments
         self.masterKeyPlain = SecureBinaryData( \
                           ReconstructSecret(pfrags, self.M, len(pfrags[0])))
   
         if not calcEKeyID(self.masterKeyPlain)==self.ekeyID:
            LOGERROR('Not all passphrases correct.')
            self.masterKeyPlain.destroy()
            return False
         
         if justVerify:
            self.masterKeyPlain.destroy()
         else:
            self.relockAtTime = RightNow() + self.lockTimeout
   
      except:
         LOGEXCEPT('Failed to unlock wallet')
         self.masterKeyPlain.destroy()
         return False
      finally:
         # Always clear the decrypted fragments
         pfrags = None

      return True
      

   #############################################################################
   def lock(self, sbdPasswdList=None):
      LOGDEBUG('Locking encryption key %s', self.ekeyID)
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
      bp.put(BINARY_CHUNK, self.ekeyID, widthBytes= 8)
      bp.put(UINT8,        self.M)
      bp.put(UINT8,        self.N)
      for i in range(N):
         bp.put(VAR_STR, self.einfos[i].serialize())
         bp.put(VAR_STR, self.efrags[i].toBinStr())
         bp.put(VAR_UNICODE, self.labels[i])

      return bp.getBinaryString()


   #############################################################################
   def unserialize(self, strData):
      bu = makeBinaryUnpacker(strData)
      ekeyID = bu.get(BINARY_CHUNK,  8)
      M      = bu.get(UINT8)
      N      = bu.get(UINT8)
   
      einfos = []
      efrags = []
      labels = []
      for i in range(N):
         einfos.append(ArmoryCryptInfo().unserialize(bp.get(VAR_STR)))
         efrags.append(SecureBinaryData(bp.get(VAR_STR)))
         labels.append(bp.get(VAR_UNICODE))
         
      self.__init__(ekeyID, M, einfos, efrags, labels)
      return self


   #############################################################################
   def CreateNewMultiPwdKey(self, efragKdfID, encryptFragAlgo, 
                                  M, N, sbdPasswdList, labelList, 
                                  preGenKey=None):

      """
      This method assumes you already have a KDF you want to use and is 
      referenced by the first arg.  If not, please create the KDF and
      add it to the wallet first (and register it with KdfObject before 
      using this method).  All passwords are stretched with the same KDF,
      though they will use different salt, and hence need diff einfo objects.
      """

      LOGINFO('Generating new multi-password master key')

      # Confirm we have N passwords and N labels
      if not len(sbdPasswdList)==N:
         raise BadInputError('Expected %d passwords, only %d provided' % \
                                          (N, len(sbdPasswdList)))

      if not len(labelList)==N:
         raise BadInputError('Expected %d labels, only %d provided' % \
                                          (N, len(labelList)))


      # Check for the existence of the specified KDF      
      if not KdfObject.kdfIsRegistered(kdfID):
         LOGERROR('Cannot create new master key without KDF.  Use') 
         LOGERROR('KdfObject().createNewKDF("ROMixOv2", targSec=X, maxMem=Y)')
         raise KdfError('Unregistered KDF: %s' % kdfID)


      # Check that we recognize the encryption algorithm
      # This will be AES256CBC, etc... used to encrypt frags
      if not encryptFragAlgo in KNOWN_CRYPTO:
         LOGERROR('Unrecognized crypto algorithm: %s', encryptFragAlgo)
         raise UnrecognizedCrypto

         
      # Create the crypt info objs for the fragments (use same encrypt algo)
      self.einfos  = []
      for i in range(N):
      # Create placeholder for master key to be encrypted and stored in file
      newKeyPlain = NULLSBD()

      try:
         # Create the new master key and frag it
         if preGenKey:
            newKeyPlain = preGenKey.copy()
         else:
            newKeyPlain = SecureBinaryData().GenerateRandom(32)

         plainFrags = SplitSecret(newKeyPlain.toBinStr(), M, N, 32)
         self.efrags = []
         for i in range(N):
            iv = SecureBinaryData().GenerateRandom(8)
            einfo = ArmoryCryptInfo(kdfID, encryptFragAlgo, 'PASSWORD', iv)
            pfrag = SecureBinaryData(plainFrags[i])

            self.efrags.append(einfo.encrypt(pfrag, sbdPasswdList[i]))
            self.einfos.append(einfo)
            self.labels.append(labelList[i])
            pfrag.destroy()

         # Forget the plain frags
         plainFrags = None

         self.ekeyID = calcEKeyID(newKeyPlain)
         # Plain master key destroyed in finally-clause

      except:
         LOGEXCEPT('Error creating multipwd key')
      finally:
         newKeyPlain.destroy()

      LOGINFO('Finished creating new master key:')
      LOGINFO('\tKDF:     %s', binary_to_hex(kdfID))
      LOGINFO('\tCrypto:  %s', encryptFragAlgo)

      return self


   #############################################################################
   def changePassphrasesAndOrKdf(oldPassList, newPassList, newLabels=None, 
                                            newKdfID=None, newEncryptAlgo=None):
      """
      This might be used in the situation that one or more of the pwd-holders
      forgets their password.  As long as there's still M people who know their
      password, they can reset all the passwords (reconstruct the MKEK, then
      re-fragment it and encrypt the pieces with the new password list)

      As before, the old password list still must have N elements, but only
      M of them need to be non-empty.  This is because the index in the 
      password list is the X-value used for SSS reconstruction.  

      Technically, the new password list should probably be full, but I 
      guess it doesn't have to be.  The fragments are deterministic, meaning
      we can recompute the frags again from the MKEK and know that we are 
      getting the same frags.  Thus we only have to re-encrypt the frags that
      are changing passwords.  But that adds quite a bit of complexity to
      this code, so for now we expect it 
      """

      if not self.unlock(self, oldPassList):
         raise PassphraseError('At least one passphrase was wrong!')

      if newKdfID is None:
         # All keys are stretched with the same KDF, can just grab first one
         newKdfID = self.einfos[0].kdfObjID

      if newEncryptAlgo is None:
         # All frags are encrypted with same algo, can just grab first one
         newEncryptAlgo = self.einfos[0].encryptAlgo

      if newLabels is None:
         newLabels = self.labels[:]

      if sum([ (1 if p.getSize()==0 else 0)  for p in newPassList]) > 0:
         raise PassphraseError('All new passwords must be non-empty')

      # Not creating a new key, but the process is the same; use preGenKey arg
      self.CreateNewMultiPwdKey(newKdfID,
                                newEncryptAlgo,
                                self.M, self.N,
                                newPassList,
                                newLabels,
                                preGenKey=self.masterKeyPlain)

      self.lock()
      



#############################################################################
#############################################################################
class ZeroData(object):
   """
   Creates a chunk of zeros of size nBytes.  But to ensure it can be 
   unserialized without knowing its size, we put it's VAR_INT size 
   up front, and then write nBytes of zeros minus the VAR_INT size.
   """
   def __init__(self, nBytes=0):
      self.nBytes = nBytes


   def serialize(self):
      if self.nBytes==0:
         raise UninitializedError

      viSize = packVarInt(self.nBytes)[1]
      bp = BinaryPacker()
      bp.put(VAR_INT, self.nBytes)
      bp.put(BINARY_CHUNK, '\x00'*(self.nBytes - viSize))
      return bp.getBinaryString()

   
   def unserialize(self, zeroStr):
      bu = makeBinaryUnpacker(zeroStr)

      # We do the before/after thing in case a non-canonical VAR_INT was
      # used.  Such as using a 4-byte VAR_INT to represent what only need
      # a 2-byte VAR_INT
      beforeVI = bu.getPosition()
      nb = bu.get(VAR_INT)
      afterVI = bu.getPosition()
      viSize = afterVI - beforeVI
      zstr = bu.get(BINARY_CHUNK, nb - viSize)

      if not zstr=='\x00'*(nb-viSize):
         LOGERROR('Expected all zero bytes, but got something else')
      
      self.__init__(nb)
      return self
      


   


#############################################################################
#############################################################################
class RootRelationship(object):
   """
   A simple structure for storing the fingerprints of all the siblings of 
   multi-sig wallet.  Each wallet chain that is part of this multi-sig 
   should store a multi-sig flag and the ID of this object.    If a chain
   has RRID zero but the multi-sig flag is on, it means that it was
   generated to be part of a multi-sig but not all siblings have been 
   acquired yet.

   This object can be transferred between wallets and will be ignored if
   none of the chains in the wallet use it.  Or transferred with all the
   public chains to fully communicate a watching-only version of the 
   multi-sig.  
   """
   def __init__(self, M=None, N=None, siblingList=None, labels=None):
      self.M = M if M else 0
      self.N = N if N else 0
      self.relID     = NULLSTR(8)
      self.randID    = SecureBinaryData().GenerateRandom(8)
      self.siblings  = []
      self.sibLabels = []


      if siblingList is None:
         siblingList = []

      if labels is None:
         labels = []

      if len(siblingList) > 15:
         LOGERROR('Cannot have more than 15 wallets in multisig!')
         return

      self.siblings  = siblingList[:]
      self.sibLabels = labels[:]

      for sib in self.siblings:
         if not len(sib)==20:
            LOGERROR('All siblings must be specified by 20-byte hash160 values')
            return


   def computeRelID(self):
      self.relID = binary_to_base58(hash256(self.serialize()))[:8]
      return self.relID

      

   def addSibling(sibRootID, label):
      if len(self.siblings) >= self.N:
         raise BadInputError('RR already has %d siblings' % self.N)

      self.siblings.append(sibRootID)
      self.labels.append(label)

      if len(self.siblings) == self.N:
      self.siblings.sort()
          


   def serialize(self):
      bp = BinaryPacker()
      bp.put(BINARY_CHUNK, self.relID, widthBytes=8)
      bp.put(BINARY_CHUNK, self.randID, widthBytes=8)
      bp.put(UINT8, self.M)
      bp.put(UINT8, self.N)
      bp.put(UINT8, len(self.siblings))
      for i in range(len(self.siblings)):
         bp.put(VAR_STR, self.siblings[i])
         bp.put(VAR_STR, self.labels[i])

      return bp.getBinaryString()


   def unserialize(self, theStr):
      bu = makeBinaryUnpacker(theStr)
      relID = bu.get(BINARY_CHUNK, 8)
      rndID = bu.get(BINARY_CHUNK, 8)
      M = bu.get(UINT8)
      N = bu.get(UINT8)
      nsib = bu.get(UINT8)
      sibList = []
      lblList = []
      for i in range(nsib):
         sibList.append(bu.get(VAR_STR))
         lblList.append(bu.get(VAR_STR))

      self.__init__(M, N, sibList, lblList)
      return self


      



#############################################################################
class ArmoryAddress(object):

   def __init__(self):
      pass


PRIV_KEY_AVAIL = enum('None', 'Plain', 'Encrypted', 'NextUnlock')
AEKTYPE = enum('Uninitialized', 'BIP32', 'ARMORY135', 'JBOK')

################################################################################
################################################################################
class ArmoryExtendedKey(object):
   def __init__(self):
      self.isWatchOnly     = False
      self.privCryptInfo   = ArmoryCryptInfo(None)
      self.sbdPrivKeyPlain = NULLSBD()
      self.sbdPrivKeyCrypt = NULLSBD()
      self.sbdPublicKey33  = NULLSBD()
      self.sbdChaincode    = NULLSBD()
      self.aekParent       = None
      self.derivePath      = []
      self.useUncompressed = False
      self.aekType         = AEKTYPE.Uninitialized
      self.keyLifetime     = 10
      self.relockAtTime    = 0

      self.walletFileRef   = None  # ref to the ArmoryWalletFile for this key

   #############################################################################
   def createFromKeyPair(self, cppExtKeyObj):
      

   # spawnChild defined in derived classes
   #def spawnChild(self, childID, ekeyObj=None, keyData=None, privSpawnReqd=False):
      #if self.aekType==AEKTYPE.JBOK:
         ## It's not that we can't do this -- just call SecureRandom(32).  
         ## It's that we don't support JBOK wallets because they're terrible
         #raise NotImplementedError('Cannot spawn from JBOK key.')
      


   #############################################################################
   def getPrivKeyAvailability(self):
      if self.isWatchOnly:
         return PRIV_KEY_AVAIL.None
      elif self.sbdPrivKeyPlain.getSize() > 0:
         return PRIV_KEY_AVAIL.Plain
      elif self.sbdPrivKeyCrypt.getSize() > 0:
         return PRIV_KEY_AVAIL.Encrypted
      else:
         return PRIV_KEY_AVAIL.NextUnlock


   #############################################################################
   def useEncryption(self):
      return self.privCryptInfo.useEncryption()
         

   #############################################################################
   def getSerializedPubKey(self, serType='hex'):
      """
      The various public key serializations:  "hex", "xpub"
      """
      if useUncompressed:
         pub = CryptoECDSA().UncompressPoint(self.sbdPublicKey33).copy()
      else:
         pub = self.sbdPublicKey33.copy()
         
      if serType.lower()=='hex':
         return pub.toHexStr()

      elif serType.lower()=='xpub':
         raise NotImplementedError('Encoding not implemented yet')
         
   #############################################################################
   def getSerializedPrivKey(self, serType='hex'):
      """
      The various private key serializations: "hex", "sipa", "xprv"
      """

      if self.useEncryption() and self.isLocked():
         raise WalletLockError('Cannot serialize locked priv key')

      lastByte = '' if self.useUncompressed else '\x01'
      binPriv = self.sbdPrivKeyPlain.toBinStr() + lastByte
         
      if serType.lower()=='hex':
         return binary_to_hex(hexPriv)
      elif serType.lower()=='sipa':
         binSipa '\x80' + binPriv + computeChecksum('\x80' + binPriv)
         return binary_to_hex(binSipa)
      elif serType.lower()=='xprv':
         raise NotImplementedError('xprv encoding not yet implemented')


   #############################################################################
   def getPrivateKeyPlain(self, ekeyObj):
      """
      NOTE:  This returns an SBD object which needs to be .destroy()ed by
             the caller when it is finished with it.
      """
      if self.ekeyObj.isLocked():
         raise KeyDataError('Master ekey must be unlocked to fetch priv key')

      
      

   #############################################################################
   def lock(self):
      if self.sbdPrivKeyCrypt.getSize()==0:
         raise KeyDataError('No encrypted form of priv key available')

   #############################################################################
   def unlock(self, ekeyObj, keyData, justVerify=False):
      if self.sbdPrivKeyPlain.getSize() > 0:
         # Already unlocked, just extend the lifetime in RAM
         if not justVerify:
            self.relockAtTime = RightNow() + self.keyLifetime
         return


      keyType,keyID = self.privCryptInfo.getEncryptKeySrc()
      if keyType == CRYPT_KEY_SRC.EKEY_OBJ:
         if ekeyObj is None:
            raise KeyDataError('Need ekey obj to unlock, but is None')

         if not keyID == ekeyObj.getEkeyID():
            raise KeyDataError('Incorrect ekey to unlock address')
               
               
      self.sbdPrivKeyPlain = \
            self.privCryptInfo.decrypt(self.sbdPrivKeyCrypt, 
                                       keyData,
                                       self.sbdPublicKey33.getHash256()[:16], 
                                       ekeyObj)
      if justVerify:
         self.sbdPrivKeyPlain.destroy()
      else:
         self.relockAtTime = RightNow() + self.keyLifetime




################################################################################
class AddressLabel(object):
  
   FILECODE = 'LABL' 

   def __init__(self, label=''):
      self.set(label)

   def set(self, lbl):
      self.label = toUnicode(lbl)

   def serialize(self):
      bp = BinaryPacker()
      bp.put(VAR_UNICODE, self.label)
      return bp.getBinaryString()

   def unserialize(self, theStr):
      bu = makeBinaryUnpacker(theStr)
      self.label = bu.get(VAR_UNICODE)
      return self.label


################################################################################
class TxComment(object):

   FILECODE = 'COMM'

   def __init__(self, comm=''):
      self.set(comm)

   def set(self, comm):
      self.comm = toUnicode(comm)

   def serialize(self):
      bp = BinaryPacker()
      bp.put(VAR_UNICODE, self.comm)
      return bp.getBinaryString()

   def unserialize(self, theStr):
      bu = makeBinaryUnpacker(theStr)
      self.comm = bu.get(VAR_UNICODE)
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
      bp.put(UINT64,          self.flags.toValue()) #widthBytes=  8
      bp.put(UINT64,          self.createTime)      #widthBytes = 8
      return bp.getBinaryString()

   #############################################################################
   def unserialize(self, theStr):
      toUnpack = makeBinaryUnpacker(theStr)
      self.fileID     = bp.get(BINARY_CHUNK, 8)
      self.armoryVer  = bp.get(UINT32)
      magicbytes      = bp.get(BINARY_CHUNK, 4)
      flagsInt        = bp.get(UINT64)
      self.createTime = bp.get(UINT64)

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
################################################################################
class Armory135ExtendedKey(ArmoryExtendedKey):

   EXTKEYTYPE = 'ARMRY135'

   #############################################################################
   def __init__(self, *args, **kwargs):
      super(Armory135ExtendedKey, self).__init__(*args, **kwargs)
      self.useUncompressed = True
      self.derivePath = None
      self.chainIndex = None




   #############################################################################
   def spawnChild(self, ekeyObj=None, keyData=None, privSpawnReqd=False):
      """
      We require some fairly complicated logic here, due to the fact that a
      user with a full, private-key-bearing wallet, may try to generate a new
      key/address without supplying a passphrase.  If this happens, the wallet
      logic gets mucked up -- we don't want to reject the request to
      generate a new address, but we can't compute the private key until the
      next time the user unlocks their wallet.  Thus, we have to save off the
      data they will need to create the key, to be applied on next unlock.
      """

      TimerStart('spawnChild_135')
      startedLocked = False

      # If the child key corresponds to a "hardened" derivation, we require
      # the priv keys to be available, or sometimes we explicitly request it
      if privSpawnReqd:
         if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.None:
            raise KeyDataError('Requires priv key, but this is a WO ext key')

         if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.Encrypted and \
            ekeyObj is None and \
            keyData is None)
            raise KeyDataError('Requires priv key, no way to decrypt it')
         

      if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.NextUnlock:
         if self.aekParent is None:
            raise KeyDataError('No parent defined from which to derive this key')

         if self.childID is None:
            raise KeyDataError('No derivation path defined to derive this key')

         # Recurse up the chain to extend from the last-fully-derived priv key
         aek = self.aekParent.spawnChild(ekeyObj, keyData, privSpawnReqd)
            
         if not aek.sbdPublicKey33.toBinStr() == self.sbdPublicKey33.toBinStr():
            raise keyData('Derived key supposed to match this one but does not')
   
         self.sbdPrivKeyPlain = aek.sbdPrivKeyPlain.copy()
         self.sbdPrivKeyCrypt = aek.sbdPrivKeyCrypt.copy()
         startedLocked = True  # if needed to derive, it was effectively locked
                              
      # If the key is currently encrypted, going to need to unlock it
      if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.Encrypted:
         unlockSuccess = self.unlock(ekeyObj, keyData)
         if not unlockSuccess:
            raise PassphraseError('Incorrect decryption data to spawn child')
         else:
            startedLocked = True  # will re-lock at the end of this operation


      sbdPubKey65 = CryptoECDSA().UncompressPoint(self.sbdPublicKey33)
      logMult1 = NULLSBD()
      logMult2 = NULLSBD()

      CECDSA = CryptoECDSA()
      if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.Plain:
         extendFunc = CECDSA.ComputeChainedPrivateKey
         extendArgs = [self.sbdPrivKeyPlain, self.sbdChaincode, sbdPubKey65, logMult1]
         extendType = 'Private'
      elif self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.None
         extendFunc = CECDSA.ComputeChainedPublicKey
         extendArgs = [sbdPubKey65, self.sbdChaincode, logMult1]
         extendType = 'Public'
         
   
         sbdNewKey1 = extendFunc(*extendArgs)
         sbdNewKey2 = extendFunc(*extendArgs)

         if sbdNewKey1.toBinStr() == sbdNewKey2.toBinStr():
            sbdNewKey2.destroy()
            with open(MULT_LOG_FILE,'a') as f:
               f.write('%s chain (pkh, mult): %s,%s\n' % (extendType, logMult1.toHexStr()))
         else:
            LOGCRIT('Chaining failed!  Computed keys are different!')
            LOGCRIT('Recomputing chained key 3 times; bail if they do not match')
            sbdNewKey1.destroy()
            sbdNewKey2.destroy()
            logMult3 = SecureBinaryData()

            sbdNewKey1 = extendFunc(*extendArgs)
            sbdNewKey2 = extendFunc(*extendArgs)
            sbdNewKey3 = extendFunc(*extendArgs)
            LOGCRIT('   Multiplier1: ' + logMult1.toHexStr())
            LOGCRIT('   Multiplier2: ' + logMult2.toHexStr())
            LOGCRIT('   Multiplier3: ' + logMult3.toHexStr())

            if sbdNewKey1==sbdNewKey2 and sbdNewKey1==sbdNewKey3:
               sbdNewKey2.destroy()
               sbdNewKey3.destroy()
               with open(MULT_LOG_FILE,'a') as f:
                  f.write('Computed chain (pkh, mult): %s,%s\n' % (a160hex,logMult1.toHexStr()))
            else:
               sbdNewKey1.destroy()
               sbdNewKey2.destroy()
               sbdNewKey3.destroy()
               # This should crash just about any process that would try to use it
               # without checking for empty private key. 
               raise KeyDataError('Chaining %s Key Failed!' % extendType)

      if extendType=='Private':
         sbdNewPriv  = sbdNewKey1.copy()
         sbdNewPub   = CryptoECDSA().ComputePublicKey(sbdNewPriv)
         sbdNewChain = self.sbdChaincode.copy()
      else:
         sbdNewPriv  = NULLSBD()
         sbdNewPub   = sbdNewKey1.copy()
         sbdNewChain = self.sbdChaincode.copy()

      childAddr = Armory135ExtendedKey(privKey=sbdNewPriv, 
                                       pubKey=sbdNewPub, 
                                       chain=sbdNewChain)
                                        
      childAddr.chainIndex = self.chainIndex + 1
      childAddr.aekParent      = self
      childAddr.aekParentID    = self.getExtKeyID()
      childAddr.privCryptInfo  = self.privCryptInfo
      childAddr.isInitialized  = True

      if startedLocked:
         childAddr.lock(ekeyObj, keyData)
         childAddr.unlock(ekeyObj, keyData)
         childAddr.lock(ekeyObj, keyData)

      return childAddr


################################################################################
################################################################################
class ArmoryBip32ExtendedKey(ArmoryExtendedKey):

   EXTKEYTYPE = 'ARMBIP32'
   def __init__(self, *args, **kwargs):
      super(ArmoryBip32ExtendedKey, self).__init__(*args, **kwargs)


   #############################################################################
   def spawnChild(self, childID, ekeyObj=None, keyData=None, privSpawnReqd=False):
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
      startedLocked = False

      if self.aekType==AEKTYPE.JBOK:
         # It's not that we can't do this -- just call SecureRandom(32).  
         # It's that we don't support JBOK wallets because they're terrible
         raise NotImplementedError('Cannot spawn from JBOK key.')
      
      # If the child key corresponds to a "hardened" derivation, we require
      # the priv keys to be available, or sometimes we explicitly request it
      if privSpawnReqd or (childID & 0x80000000 > 0):
         if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.None:
            raise KeyDataError('Requires priv key, but this is a WO ext key')

         if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.Encrypted and \
            ekeyObj is None and \
            keyData is None)
            raise KeyDataError('Requires priv key, no way to decrypt it')
         

      if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.NextUnlock:
         if self.aekParent is None:
            raise KeyDataError('No parent defined from which to derive this key')

         if self.derivePath is None:
            raise KeyDataError('No derivation path defined to derive this key')

         # Recurse up the derivation path to derive the parent(s)
         if self.aekType == AEKTYPE.BIP32:
            if self.derivePath is None:
               raise KeyDataError('No derivation path defined to derive this key')
            aek = self.aekParent.spawnChild(self.derivePath[-1], ekeyObj, keyData)
         elif self.aekType == AEKTYPE.ARMORY135:
            aek = self.aekParent.spawnChild(0, ekeyObj, keyData)
            

         if not aek.sbdPublicKey33.toBinStr() == self.sbdPublicKey33.toBinStr():
            raise keyData('Derived key supposed to match this one but does not')
   
         self.sbdPrivKeyPlain = aek.sbdPrivKeyPlain.copy()
         self.sbdPrivKeyCrypt = aek.sbdPrivKeyCrypt.copy()
         startedLocked = True  # if needed to derive, it was effectively locked
                              
      # If the key is currently encrypted, going to need to unlock it
      if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.Encrypted:
         unlockSuccess = self.unlock(ekeyObj, keyData)
         if not unlockSuccess:
            raise PassphraseError('Incorrect decryption data to spawn child')
         else:
            startedLocked = True  # will re-lock at the end of this operation


         
      childAddr.childIdentifier
      extChild  = HDWalletCrypto().ChildKeyDeriv(self.getExtendedKey(), childID)

      # In all cases we compute a new public key and chaincode
      childAddr.binPubKey33  = extChild.getPub().copy()
      childAddr.binChaincode = extChild.getChain().copy()

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
         if not startedLocked:
            childAddr.unlock(ekeyObj, keyData)
            self.unlock(ekeyObj, keyData)

      return ArmoryExtendedKey(
      return childAddr

   #############################################################################
   def getWalletLocator(self, encryptWithParentChain=True)
      """
      @encryptWithParentChain:

      The wallet locator information is really intended for the online
      computer to identify to an offline computer that certain public
      keys are a related to the wallet.  The problem is that the data
      passes by a lot of unrelated parties on the way and wallet locators
      with the same IDs or similar paths could leak privacy information.
      However, both online and offline computer have data that no one
      else should know: the chaincode.  So we simply put a unique 
      identifier up front, and then encrypt the thing using the chaincode
      of the parent/root as the AES256 key.  The offline computer will 
      attempt to decrypt all wallet locators strings with the chaincode,
      and if it succeeds, it will use the locator information as needed.
      If you are unrelated to the wallet, it will look like random data.

      One problem is that some devices may only have floating branches 
      of a BIP32 wallet, and wouldn't recognize the root.  In other cases
      we might have a system with thousands of wallets, and attempting 
      decryption with every chain code might be excessive.   So we 
      actually encrypt every sub-path:  i.e.

         encrypt_m_x("y/z/a") | encrypt_m_x_y("z/a") | encrrypt_m_x_y_z("a")

      The whole thing is the wallet locator, and if the wallet has no
      floating chains, it only needs to attempt decryption of the first
      16 bytes for each root (should be a small number).  
      """
   
      if encryptWithParentChain:
         self.



################################################################################
################################################################################
class ArmoryImportedKey(ArmoryExtendedKey):

   EXTKEYTYPE = 'IMPORTED'


# Root modes represent how we anticipate using this root.  An Armory root
# marked as BIP32_Root means it is the top of a BIP32 tree generated from a 
# seed value.  If it is marked as BIP32_Floating, it means it is a branch 
# of BIP32 tree for which we don't have the rootroot (maybe it's a piece 
# of a BIP32 tree belonging to someone else given to us to generate payment 
# addresses, or for a multisig wallet.  ARM135 is the old Armory wallet 
# algorithm that was used for the first 2-3 years of Armory's existence.  
# JBOK stands for "Just a bunch of keys" (like RAID-JBOD).  JBOK mode will
# most likely only be used for imported keys and old Bitcoin Core wallets.
ROOTTYPE = enum('BIP32_Root', 'BIP32_Floating', 'ARM135_Root', 'JBOK')

#############################################################################
class ArmoryRoot(ArmoryExtendedKey):
      
   FILECODE = 'ROOT'

   def __init__(self):
      super(ArmoryRoot, self).__init__()

      # General properties of this root object
      self.createDate = 0
      self.labelName   = ''
      self.labelDescr  = ''

      # Each root is a candidate for being displayed to the user, should 
      # have a Base58 ID
      self.uniqueIDBin = ''
      self.uniqueIDB58 = ''    # Base58 version of reversed-uniqueIDBin

      # If this root is intended to be used in multi-sig, it should be flagged
      # In some cases this root will be created with the intention to become
      # part of a multisig wallet.  In that case, multisig flag will be on,
      # but the relationshipID will be zeros.  Once a relationship is defined
      # and added to the wallet, this structure will be updated.
      self.isMultisig      = False
      self.relationshipID  = NULLSTR(8)

      # If this is a "normal" wallet, it is BIP32.  Other types of wallets 
      # (perhaps old Armory chains, will use different name to identify we
      # may do something different)
      self.rootType = ROOTTYPE.BIP32_Root

      # Extra data that needs to be encrypted, if 
      self.seedCryptInfo   = ArmoryCryptInfo(None)
      self.bip32seed_plain = SecureBinaryData(0)
      self.bip32seed_encr  = SecureBinaryData(0)
      self.bip32seed_size  = 0

      # This helps identify where in the BIP 32 tree this node is.
      self.rootID   = NULLSTR(8)
      self.parentID = NULLSTR(8)
      self.rootPath = []

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

      
      # 
      self.wltFileRef = None


      """ # Old pybtcwallet stuff
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
                                 ekeyObj=None, keyData=None, seedBytes=20,
                                 extraEntropy=None):
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

      # Uses Crypto++ PRNG -- which is suitable for cryptographic purposes.
      # 16 bytes is generally considered enough, though we add 4 extra for 
      # some margin.  We also have the option to add some extra entropy 
      # through the last command line argument.  We use this in ArmoryQt
      # and armoryd by pulling key presses and volatile system files
      if extraEntropy is None:
         extraEntropy = NULLSBD() 

      self.bip32seed_plain  = SecureBinaryData().GenerateRandom(seedBytes, 
                                                                extraEntropy)

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
      if cryptInfo is None:
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
