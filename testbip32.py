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

M0 = CKD(M, 0)
M01a = CKD(M, 0, 1)
M01b = CKD(M0, 1)

M0.debugPrint()
M01a.debugPrint()
M01b.debugPrint()
