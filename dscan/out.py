#!/usr/bin/env python3
# encoding: utf-8

"""
out.py
Display the information and status.
"""
import sys


class Display:
    """
    Context is displayed as a table.
    """
    CLEAR_SCREEN = "\033c"
    CLEAR_CURRENT_LINE = "\033[1K\033[0G"
    TITLE = "Distributed Scan Status"

    STAGES_HEADERS = [
        "Nº Stages", "Nº Pending Tasks", "Completion %"
    ]

    ACTIVE_STAGES_HEADERS = [
        'Stage', "Nº Targets", "Nº Finished", "Completion %"
    ]

    TASK_HEADERS = [
        "Agent", "Stage", "Task Status", "Target Ip"
    ]

    def __init__(self, context):
        self.ctx = context

    def inline(self, message):
        sys.stdout.write(self.CLEAR_CURRENT_LINE)
        sys.stdout.write(f"message:\t{message}")
        sys.stdout.flush()

    @staticmethod
    def print_title(title):
        title_length = len(title)
        sys.stdout.write("\n\n")
        sys.stdout.write("%s\n" % title.ljust(title_length))
        sys.stdout.write("%s\n\n" % ("=" * title_length))

    def print_table(self, headers, data, clear=False):
        result = []
        names = list(headers)
        result.append(names)
        result.extend(list(map(str, row)) for row in data)

        lens = [list(map(len, row)) for row in result]
        field_lens = list(map(max, zip(*lens)))
        result.insert(0, ['-' * length for length in field_lens])
        result.insert(2, ['-' * length for length in field_lens])

        format_string = "\t".join(
            '{%d:%ds}' % item for item in enumerate(field_lens))

        if clear:
            sys.stdout.write(self.CLEAR_SCREEN)
            title_length = len(self.TITLE)
            sys.stdout.write("\n\n")
            sys.stdout.write("%s\n" % self.TITLE.ljust(title_length))
            sys.stdout.write("%s\n\n" % ("=" * title_length))

        sys.stdout.write(
            '\n'.join(format_string.format(*row) for row in result))
        sys.stdout.write("\n\n")
        sys.stdout.flush()

    def show(self):
        self.print_table(self.STAGES_HEADERS, self.ctx.ctx_status(), True)
        self.print_table(self.ACTIVE_STAGES_HEADERS,
                         self.ctx.active_stages_status())
        self.print_table(self.TASK_HEADERS, self.ctx.tasks_status())