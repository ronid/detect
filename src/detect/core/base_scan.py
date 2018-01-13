import logbook
import inspect
import datetime as dt


class ScanMeta(type):
    NETWORK_SCANS = dict()
    HOST_SCANS = dict()

    def __new__(cls, name, bases, attrs):
        new_class = super(ScanMeta, cls).__new__(cls, name, bases, attrs)
        if name != 'Scan':
            signature = inspect.signature(new_class.run)
            if 'target' in signature.parameters:
                cls.HOST_SCANS[name] = new_class
            else:
                cls.NETWORK_SCANS[name] = new_class
        return new_class


class Scan(object, metaclass=ScanMeta):
    NAME = None

    def __init__(self):
        self.logger = logbook.Logger(self.NAME)

    def _run(self, *args, **kwargs):
        start = dt.datetime.now()
        scan_result = self.run(*args, **kwargs)
        scan_result.took = dt.datetime.now() - start
        return scan_result

    def run(self, *args, **kwargs):
        raise NotImplementedError()
