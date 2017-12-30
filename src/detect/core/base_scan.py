import logbook


class ScanMeta(type):
    SCANS = dict()

    def __new__(cls, name, bases, attrs):
        new_class = super(ScanMeta, cls).__new__(cls, name, bases, attrs)
        if name != 'Scan':
            cls.SCANS[name] = new_class
        return new_class


class Scan(object, metaclass=ScanMeta):
    NAME = None

    def __init__(self):
        self.logger = logbook.Logger(self.NAME)

    def run(self, *args, **kwargs):
        raise NotImplementedError()
