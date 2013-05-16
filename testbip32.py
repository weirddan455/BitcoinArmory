from armoryengine import *
from CppBlockUtils import ExtendedKey, HDWalletCrypto


rootPub = SecureBinaryData(hex_to_binary('04'
   '180b25d6eb80500a9b61703ac220828536a535f0834aaad527676800bc176992'
   '0f316f4df5bec623941897ab53e25980a6ff4f01b4e34fc3fbe23047b34b03c2'))
rootChain = SecureBinaryData(hex_to_binary('9733f9a9416b32f4de6119177c58bc88104d64a467b351754ee227ab3662d69a'))


M = ExtendedKey().CreateFromPublic(rootPub, rootChain)
M.debugPrint()


def CKD(ekey, *args):
   newKey = ekey.copy()
   for a in args:
      newKey = HDWalletCrypto().ChildKeyDeriv(newKey, a)
   return newKey.copy()

M0   = CKD(M, 0)
M00  = CKD(M, 0, 0)
M00a = CKD(M0,   0)
M01  = CKD(M, 0, 1)

M0.debugPrint()
M00.debugPrint()
M00a.debugPrint()

pmatch1 = M00.getPub().toHexStr()
pmatch2 = M00a.getPub().toHexStr()
print pmatch1
print pmatch2
print pmatch1==pmatch2



print ''
print '*'*80
print '* M/* chain'
for i in range(5):
   print 'M/%d: ' % i, 
   new = CKD(M, i)
   print new.getPub().toHexStr()[:40]
   
print ''
print '*'*80
print '* M/0/* chain'
for i in range(5):
   print 'M/0/%d: ' % i, 
   ekey=CKD(M,0,i)
   print ekey.getPub().toHexStr()[:20]

print ''
print '*'*80
print '* M/0/0/* chain'
for i in range(5):
   print 'M/0/0/%d: ' % i, 
   print CKD(M, 0, 0, i).getPub().toHexStr()[:20]

