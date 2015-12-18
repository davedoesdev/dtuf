class DTufError(Exception):
    pass

class DTufReservedTargetError(DTufError):
    def __init__(self, target):
        super(DTufReservedAliasError, self).__init__()
        self._target = target

    def __str__(self):
        return 'target %s is reserved' % self._target
