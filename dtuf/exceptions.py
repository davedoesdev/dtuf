class DTufError(Exception):
    pass

class DTufReservedAliasError(DTufError):
    def __init__(self, alias):
        super(DTufReservedAliasError, self).__init__()
        self._alias = alias

    def __str__(self):
        return 'alias %s is reserved' % self._alias
