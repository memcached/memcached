#!/usr/bin/env python

import breakdancer
from breakdancer import Condition, Effect, Action, Driver

TESTKEY = 'testkey'

######################################################################
# Conditions
######################################################################

class ExistsCondition(Condition):

    def __call__(self, state):
        return TESTKEY in state

class ExistsAsNumber(Condition):

    def __call__(self, state):
        try:
            int(state[TESTKEY])
            return True
        except:
            return False

class MaybeExistsAsNumber(ExistsAsNumber):

    def __call__(self, state):
        return TESTKEY not in state or ExistsAsNumber.__call__(self, state)

class DoesNotExistCondition(Condition):

    def __call__(self, state):
        return TESTKEY not in state

class NothingExistsCondition(Condition):

    def __call__(self, state):
        return not bool(state)

######################################################################
# Effects
######################################################################

class StoreEffect(Effect):

    def __init__(self, v='0'):
        self.v = v

    def __call__(self, state):
        state[TESTKEY] = self.v

class DeleteEffect(Effect):

    def __call__(self, state):
        del state[TESTKEY]

class FlushEffect(Effect):

    def __call__(self, state):
        state.clear()

class AppendEffect(Effect):

    suffix = '-suffix'

    def __call__(self, state):
        state[TESTKEY] = state[TESTKEY] + self.suffix

class PrependEffect(Effect):

    prefix = 'prefix-'

    def __call__(self, state):
        state[TESTKEY] = self.prefix + state[TESTKEY]

class ArithmeticEffect(Effect):

    default = '0'

    def __init__(self, by=1):
        self.by = by

    def __call__(self, state):
        if TESTKEY in state:
            state[TESTKEY] = str(max(0, int(state[TESTKEY]) + self.by))
        else:
            state[TESTKEY] = self.default

######################################################################
# Actions
######################################################################

class Set(Action):

    effect = StoreEffect()
    postconditions = [ExistsCondition()]

class Add(Action):

    preconditions = [DoesNotExistCondition()]
    effect = StoreEffect()
    postconditions = [ExistsCondition()]

class Delete(Action):

    preconditions = [ExistsCondition()]
    effect = DeleteEffect()
    postconditions = [DoesNotExistCondition()]

class Flush(Action):

    effect = FlushEffect()
    postconditions = [NothingExistsCondition()]

class Delay(Flush):
    pass

class Append(Action):

    preconditions = [ExistsCondition()]
    effect = AppendEffect()
    postconditions = [ExistsCondition()]

class Prepend(Action):

    preconditions = [ExistsCondition()]
    effect = PrependEffect()
    postconditions = [ExistsCondition()]

class Incr(Action):

    preconditions = [ExistsAsNumber()]
    effect = ArithmeticEffect(1)
    postconditions = [ExistsAsNumber()]

class Decr(Action):

    preconditions = [ExistsAsNumber()]
    effect = ArithmeticEffect(-1)
    postconditions = [ExistsAsNumber()]

class IncrWithDefault(Action):

    preconditions = [MaybeExistsAsNumber()]
    effect = ArithmeticEffect(1)
    postconditions = [ExistsAsNumber()]

class DecrWithDefault(Action):

    preconditions = [MaybeExistsAsNumber()]
    effect = ArithmeticEffect(-1)
    postconditions = [ExistsAsNumber()]

######################################################################
# Driver
######################################################################

class EngineTestAppDriver(Driver):

    def preSuite(self, seq):
        print '#include "suite_stubs.h"'
        print ""

    def testName(self, seq):
        return 'test_' + '_'.join(a.name for a in seq)

    def startSequence(self, seq):
        f = "static enum test_result %s" % self.testName(seq)
        print ("%s(ENGINE_HANDLE *h,\n%sENGINE_HANDLE_V1 *h1) {"
               % (f, " " * (len(f) + 1)))

    def startAction(self, action):
        if isinstance(action, Delay):
            s = "    delay(expiry+1);"
        elif isinstance(action, Flush):
            s = "    flush(h, h1);"
        elif isinstance(action, Delete):
            s = '    del(h, h1);'
        else:
            s = '    %s(h, h1);' % (action.name)
        print s

    def postSuite(self, seq):
        print """MEMCACHED_PUBLIC_API
engine_test_t* get_tests(void) {

    static engine_test_t tests[]  = {
"""
        for seq in sorted(seq):
            print '        {"%s",\n         %s,\n         test_setup, teardown, NULL},' % (
                ', '.join(a.name for a in seq),
                self.testName(seq))

        print """        {NULL, NULL, NULL, NULL, NULL}
    };
    return tests;
}"""

    def endSequence(self, seq, state):
        val = state.get(TESTKEY)
        if val:
            print '    checkValue(h, h1, "%s");' % val
        else:
            print '    assertNotExists(h, h1);'
        print "    return SUCCESS;"
        print "}"
        print ""

    def endAction(self, action, state, errored):
        value = state.get(TESTKEY)
        if value:
            vs = ' // value is "%s"' % value
        else:
            vs = ' // value is not defined'

        if errored:
            print "    assertHasError();" + vs
        else:
            print "    assertHasNoError();" + vs

if __name__ == '__main__':
    breakdancer.runTest(breakdancer.findActions(globals().values()),
                        EngineTestAppDriver())
