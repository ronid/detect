import pyprinter


class ScanResult(object):
    def __init__(self, name, took=None, conclusions=()):
        self.name = name
        self.took = took
        self.conclusions = conclusions

    def __repr__(self):
        return '<{} Result>'.format(self.name)

    def pretty_print(self, printer=None):
        printer = printer or pyprinter.get_printer()

        title = '{} results'.format(self.name)
        printer.write_line(printer.CYAN + title)
        printer.write_line('=' * len(title))
        printer.write_line(printer.WHITE + 'Scan took {} seconds.'.format(self.took))
        with printer.group(3):
            for conclusion in self.conclusions:
                conclusion.pretty_print()
