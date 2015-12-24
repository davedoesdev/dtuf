class DTufError(Exception):
    pass

class DTufReservedTargetError(DTufError):
    def __init__(self, target):
        super(DTufReservedTargetError, self).__init__()
        self.target = target

    def __str__(self):
        return 'target %s is reserved' % self.target
