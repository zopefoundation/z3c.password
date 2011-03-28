##############################################################################
#
# Copyright (c) 2006 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Principal MixIn for Advanced Password Management

$Id$
"""
__docformat__ = "reStructuredText"
import datetime
import persistent.list
import zope.component
from zope.security.management import getInteraction

from z3c.password import interfaces

class PrincipalMixIn(object):
    """A Principal Mixin class for ``zope.app.principalfolder``'s internal
    principal."""

    passwordExpiresAfter = None
    passwordSetOn = None
    passwordExpired = False #force PasswordExpired,
                             #e.g. for changePasswordOnNextLogin

    failedAttempts = 0
    failedAttemptCheck = interfaces.TML_CHECK_ALL
    maxFailedAttempts = None
    lastFailedAttempt = None
    lockOutPeriod = None

    disallowPasswordReuse = None
    previousPasswords = None

    passwordOptionsUtilityName = None

    def _checkDisallowedPreviousPassword(self, password):
        if self._disallowPasswordReuse():
            if self.previousPasswords is not None and password is not None:
                #hack, but this should work with zope.app.authentication and
                #z3c.authenticator
                passwordManager = self._getPasswordManager()

                for pwd in self.previousPasswords:
                    if passwordManager.checkPassword(pwd, password):
                        raise interfaces.PreviousPasswordNotAllowed(self)

    def getPassword(self):
        return super(PrincipalMixIn, self).getPassword()

    def setPassword(self, password, passwordManagerName=None):
        self._checkDisallowedPreviousPassword(password)

        super(PrincipalMixIn, self).setPassword(password, passwordManagerName)

        if self._disallowPasswordReuse():
            if self.previousPasswords is None:
                self.previousPasswords = persistent.list.PersistentList()

            if self.password is not None:
                # storm/custom property does not like a simple append
                ppwd = self.previousPasswords
                ppwd.append(self.password)
                self.previousPasswords = ppwd

        self.passwordSetOn = self.now()
        self.failedAttempts = 0
        self.lastFailedAttempt = None
        self.passwordExpired = False


    password = property(getPassword, setPassword)

    def now(self):
        #hook to facilitate testing and easier override
        return datetime.datetime.now()

    def _isRelevantRequest(self):
        fac = self._failedAttemptCheck()
        if fac is None:
            return True

        if fac == interfaces.TML_CHECK_ALL:
            return True

        interaction = getInteraction()
        try:
            request = interaction.participations[0]
        except IndexError:
            return True # no request, we regard that as relevant.

        if fac == interfaces.TML_CHECK_NONRESOURCE:
            if '/@@/' in request.getURL():
                return False
            return True

        if fac == interfaces.TML_CHECK_POSTONLY:
            if request.method == 'POST':
                return True
            return False

    def checkPassword(self, pwd, ignoreExpiration=False, ignoreFailures=False):
        # keep this as fast as possible, because it will be called (usually)
        # for EACH request

        # Check the password
        same = super(PrincipalMixIn, self).checkPassword(pwd)

        # Do not try to record failed attempts or raise account locked
        # errors for requests that are irrelevant in this regard.
        if not self._isRelevantRequest():
            return same

        if not ignoreFailures and self.lastFailedAttempt is not None:
            if self.tooManyLoginFailures():
                locked = self.accountLocked()
                if locked is None:
                    #no lockPeriod
                    pass
                elif locked:
                    #account locked by tooManyLoginFailures and within lockPeriod
                    if not same:
                        self.lastFailedAttempt = self.now()
                    raise interfaces.AccountLocked(self)
                else:
                    #account locked by tooManyLoginFailures and out of lockPeriod
                    self.failedAttempts = 0
                    self.lastFailedAttempt = None

        if same:
            #successful attempt
            if not ignoreExpiration:
                if self.passwordExpired:
                    raise interfaces.PasswordExpired(self)

                # Make sure the password has not been expired
                expiresOn = self.passwordExpiresOn()
                if expiresOn is not None:
                    if expiresOn < self.now():
                        raise interfaces.PasswordExpired(self)
            add = 0
        else:
            #failed attempt, record it, increase counter
            self.failedAttempts += 1
            self.lastFailedAttempt = self.now()
            add = 1

        # If the maximum amount of failures has been reached notify the
        # system by raising an error.
        if not ignoreFailures:
            if self.tooManyLoginFailures(add):
                raise interfaces.TooManyLoginFailures(self)

        if same and self.failedAttempts != 0:
            #if all nice and good clear failure counter
            self.failedAttempts = 0
            self.lastFailedAttempt = None

        return same

    def tooManyLoginFailures(self, add = 0):
        attempts = self._maxFailedAttempts()
        #this one needs to be >=, because... data just does not
        #get saved on an exception when running under of a full Zope env.
        #the dance around ``add`` has the same roots
        #we need to be able to increase the failedAttempts count and not raise
        #at the same time
        if attempts is not None:
            attempts += add
            if self.failedAttempts >= attempts:
                return True
        return False

    def accountLocked(self):
        lockPeriod = self._lockOutPeriod()
        if lockPeriod is not None:
            #check if the user locked himself
            if (self.lastFailedAttempt is not None
                and self.lastFailedAttempt + lockPeriod > self.now()):
                return True
            else:
                return False
        return None

    def passwordExpiresOn(self):
        expires = self._passwordExpiresAfter()
        if expires is None:
            return None
        if self.passwordSetOn is None:
            return None
        return self.passwordSetOn + expires

    def _optionsUtility(self):
        if self.passwordOptionsUtilityName:
            #if we have a utility name, then it must be there
            return zope.component.getUtility(
                interfaces.IPasswordOptionsUtility,
                name=self.passwordOptionsUtilityName)
        return zope.component.queryUtility(
            interfaces.IPasswordOptionsUtility, default=None)

    def _passwordExpiresAfter(self):
        if self.passwordExpiresAfter is not None:
            return self.passwordExpiresAfter

        options = self._optionsUtility()
        if options is None:
            return self.passwordExpiresAfter
        else:
            days = options.passwordExpiresAfter
            if days is not None:
                return datetime.timedelta(days=days)
            else:
                return self.passwordExpiresAfter

    def _lockOutPeriod(self):
        if self.lockOutPeriod is not None:
            return self.lockOutPeriod

        options = self._optionsUtility()
        if options is None:
            return self.lockOutPeriod
        else:
            minutes = options.lockOutPeriod
            if minutes is not None:
                return datetime.timedelta(minutes=minutes)
            else:
                return self.lockOutPeriod

    def _failedAttemptCheck(self):
        if self.failedAttemptCheck is not None:
            return self.failedAttemptCheck

        options = self._optionsUtility()
        if options is None:
            return self.failedAttemptCheck
        else:
            fac = options.failedAttemptCheck
            if fac is not None:
                return fac
            else:
                return self.failedAttemptCheck

    def _maxFailedAttempts(self):
        if self.maxFailedAttempts is not None:
            return self.maxFailedAttempts

        options = self._optionsUtility()
        if options is None:
            return self.maxFailedAttempts
        else:
            count = options.maxFailedAttempts
            if count is not None:
                return count
            else:
                return self.maxFailedAttempts

    def _disallowPasswordReuse(self):
        if self.disallowPasswordReuse is not None:
            return self.disallowPasswordReuse

        options = self._optionsUtility()
        if options is None:
            return self.disallowPasswordReuse
        else:
            dpr = options.disallowPasswordReuse
            if dpr is not None:
                return dpr
            else:
                return self.disallowPasswordReuse