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
"""Test Setup
"""
import doctest
import unittest
from doctest import DocFileSuite

from z3c.password import testing


def test_suite():
    flags = doctest.NORMALIZE_WHITESPACE |\
        doctest.ELLIPSIS |\
        doctest.IGNORE_EXCEPTION_DETAIL
    return unittest.TestSuite((
        DocFileSuite('README.txt',
                     setUp=testing.setUp, tearDown=testing.tearDown,
                     optionflags=flags),
        DocFileSuite('principal.txt',
                     setUp=testing.setUp, tearDown=testing.tearDown,
                     optionflags=flags),
    ))
