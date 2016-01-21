"""
Module containing exceptions thrown by :mod:`dtuf`.
"""

class DTufError(Exception):
    """
    Base exception class for all dtuf errors
    """
    pass

class DTufReservedTargetError(DTufError):
    """
    Target name is reserved so can't be used in :meth:`dtuf.DTufMaster.push_target`.
    """
    def __init__(self, target):
        """
        :param target: Target name
        :type target: str
        """
        super(DTufReservedTargetError, self).__init__()
        self.target = target

    def __str__(self):
        return 'target %s is reserved' % self.target
