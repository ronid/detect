import pyprinter


class ScanResult(object):
    def __init__(self, name, took, **kwargs):
        self.name = name
        self.took = took
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.parameters = kwargs.keys()

    def __repr__(self):
        return '<{} Result>'.format(self.name)

    def pretty_print(self, printer=None):
        printer = printer or pyprinter.get_printer()

        title = '{} results'.format(self.name)
        printer.write_line(printer.CYAN + title)
        printer.write_line('=' * len(title))
        printer.write_line(printer.WHITE + 'Scan took {} seconds.'.format(self.took))
        with printer.group(3):
            for key in self.parameters:
                printer.write_aligned(key, getattr(self, key), align_size=10)
