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
"""Password Utility Implementation

$Id$
"""
__docformat__ = "reStructuredText"
import difflib
import random
import string
import time
import zope.interface
from zope.schema.fieldproperty import FieldProperty

from z3c.password import interfaces


class TrivialPasswordUtility(object):
    """A trivial password utility."""
    zope.interface.implements(interfaces.IPasswordUtility)

    description = (u'All passwords are accepted and always the "trivial" '
                   u'password is generated.')

    def verify(self, new, ref=None):
        '''See interfaces.IPasswordUtility'''
        return

    def generate(self, ref=None):
        '''See interfaces.IPasswordUtility'''
        return 'trivial'


class HighSecurityPasswordUtility(object):
    """An implementation of the high-security password API."""
    zope.interface.implements(interfaces.IHighSecurityPasswordUtility)

    minLength = FieldProperty(
        interfaces.IHighSecurityPasswordUtility['minLength'])
    maxLength = FieldProperty(
        interfaces.IHighSecurityPasswordUtility['maxLength'])
    groupMax = FieldProperty(
        interfaces.IHighSecurityPasswordUtility['groupMax'])
    maxSimilarity = FieldProperty(
        interfaces.IHighSecurityPasswordUtility['maxSimilarity'])

    LOWERLETTERS = string.letters[:26]
    UPPERLETTERS = string.letters[26:]
    DIGITS = string.digits
    SPECIALS = string.punctuation

    description = (u'Passwords generated and verified by this utility conform '
                   u'strictly to the specified parameters. See the interface '
                   u'for more details.')

    def __init__(self, minLength=8, maxLength=12, groupMax=6,
                 maxSimilarity=0.6, seed=None):
        self.minLength = minLength
        self.maxLength = maxLength
        self.groupMax = groupMax
        self.maxSimilarity = maxSimilarity
        self.random = random.Random(seed or time.time())

    def verify(self, new, ref=None):
        '''See interfaces.IHighSecurityPasswordUtility'''
        # 0. Make sure we got a password.
        if not new:
            raise interfaces.NoPassword()
        # 1. Make sure the password has the right length.
        if len(new) < self.minLength:
            raise interfaces.TooShortPassword()
        if len(new) > self.maxLength:
            raise interfaces.TooLongPassword()
        # 2. Ensure that the password is sufficiently different to the old
        #    one.
        if ref is not None:
            sm = difflib.SequenceMatcher(None, new, ref)
            if sm.ratio() > self.maxSimilarity:
                raise interfaces.TooSimilarPassword()
        # 3. Ensure that the password's character set is complex enough.
        num_lower_letters = 0
        num_upper_letters = 0
        num_digits = 0
        num_specials = 0
        num_others = 0
        for char in new:
            if char in self.LOWERLETTERS:
                num_lower_letters += 1
            elif char in self.UPPERLETTERS:
                num_upper_letters += 1
            elif char in self.DIGITS:
                num_digits += 1
            elif char in self.SPECIALS:
                num_specials += 1
            else:
                num_others += 1
        if (num_lower_letters > self.groupMax or
            num_upper_letters > self.groupMax or
            num_digits > self.groupMax or
            num_specials > self.groupMax or
            num_others > self.groupMax):
            raise interfaces.TooManyGroupCharacters()
        return

    def generate(self, ref=None):
        '''See interfaces.IHighSecurityPasswordUtility'''
        verified = False
        while not verified:
            new = ''
            # Determine the length of the password
            length = self.random.randint(self.minLength, self.maxLength)
            # Generate the password
            chars = self.LOWERLETTERS + self.UPPERLETTERS + \
                    self.DIGITS + self.SPECIALS
            for count in xrange(length):
                new += self.random.choice(chars)
            # Verify the new password
            try:
                self.verify(new, ref)
            except interfaces.InvalidPassword:
                verified = False
            else:
                verified = True
        return new
