################################################################################
#
# Copyright (C) 2011-2013, Alan C. Reiner    <alan.reiner@gmail.com>
# Distributed under the GNU Affero General Public License (AGPL v3)
# See LICENSE or http://www.gnu.org/licenses/agpl.html
#
################################################################################
#
#
#
################################################################################
from armoryengine.ArmoryUtils import LOGWARN, LOGERROR


import smtplib
import os
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders
import functools

def send_email(send_from, password, send_to, subject, text):
   if not type(send_to) == list:
      raise AssertionError
   msg = MIMEMultipart()
   msg['From'] = send_from
   msg['To'] = COMMASPACE.join(send_to)
   msg['Date'] = formatdate(localtime=True)
   msg['Subject'] = subject
   msg.attach(MIMEText(text))
   mailServer = smtplib.SMTP('smtp.gmail.com', 587)
   mailServer.ehlo()
   mailServer.starttls()
   mailServer.ehlo()
   mailServer.login(send_from, password)
   mailServer.sendmail(send_from, send_to, msg.as_string())
   mailServer.close()

# Following this pattern to allow arguments to be passed to this decorator:
# http://stackoverflow.com/questions/10176226/how-to-pass-extra-arguments-to-python-decorator
def EmailOutput(send_from, password, send_to, subject='Armory Output'):
   def ActualEmailOutputDecorator(func):
      @functools.wraps(func)
      def wrapper(*args, **kwargs):
         ret = func(*args, **kwargs)
         if ret and send_from and password and send_to:
            send_email(send_from, password, send_to, subject, ret)
         return ret
      return wrapper
   return ActualEmailOutputDecorator




################################################################################
# Enforce Argument Types -- Decorator factory (for a decorator with args)
def VerifyArgTypes(**typemap):

   # If None appears in any of the type lists, replace with type(None)
   # And also convert to tuple
   for varName,typeList in typemap.iteritems():
      if isinstance(typeList, (list, tuple)):
         newTypeList = []
         for typeObj in typeList:
            if typeObj is None:
               newTypeList.append(type(None))          
            else:
               newTypeList.append(typeObj)
         typemap[varName] = tuple(newTypeList)
      
   # Create an error str to identify what arguments failed and what's expected
   def generateErrorMsg(argname, var):
      errStr = 'Argument "%s" is %s;  Expected ' % (argname, str(type(var)))
      #errStr = 'Argument "%s" is %s (expected %s)' % (aname, str(type(aname)), str(typemap[aname]))
      if isinstance(typemap[argname], (list,tuple)):
         errStr += ' or '.join([str(t) for t in typemap[argname]])
      else:
         errStr += '%s' % typemap[argname]
      return errStr

   import inspect
   # We need to return a function that has;
   #     Input:   function + args
   #     Output:  wrapped function that checks argument list for types

   
   def decorator(func):

      aspec = inspect.getargspec(func)
      for key,val in typemap.iteritems():
         if not key in aspec.args:
            raise TypeError('Function "%s" has no argument "%s"'% (func.__name__,key))


      def wrappedFunc(*args, **kwargs):
               
         for i,arg in enumerate(args):
            if i>=len(aspec.args):
               continue
            aname = aspec.args[i] 
            if aname in typemap and not isinstance(arg, typemap[aname]):
               raise TypeError(generateErrorMsg(aname, arg))

         for aname,val in kwargs.iteritems():
            if aname in typemap and not isinstance(val, typemap[aname]):
               raise TypeError(generateErrorMsg(aname, val))

         return func(*args, **kwargs)

      return wrappedFunc

   return decorator
               

         



