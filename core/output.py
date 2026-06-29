import sys
from typing import Any, Dict, List, Optional
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.markdown import Markdown
    from rich.tree import Tree
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

class Output:
    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
        self._console = Console() if RICH_AVAILABLE else None

    def _prefix(self, level: str) -> str:
        symbols = {'info': '[+]', 'warn': '[!]', 'error': '[-]', 'success': '[+]', 'debug': '[#]'}
        return symbols.get(level, '[?]')

    def info(self, message: str):
        if not self.quiet:
            ts = datetime.now().strftime('%H:%M:%S')
            print(f"{self._prefix('info')} [{ts}] {message}")

    def success(self, message: str):
        if not self.quiet:
            ts = datetime.now().strftime('%H:%M:%S')
            print(f"{self._prefix('success')} [{ts}] {message}")

    def warn(self, message: str):
        if not self.quiet:
            ts = datetime.now().strftime('%H:%M:%S')
            print(f"{self._prefix('warn')} [{ts}] {message}")

    def error(self, message: str):
        ts = datetime.now().strftime('%H:%M:%S')
        print(f"{self._prefix('error')} [{ts}] {message}", file=sys.stderr)

    def debug(self, message: str):
        if self.verbose:
            ts = datetime.now().strftime('%H:%M:%S')
            print(f"{self._prefix('debug')} [{ts}] {message}")

    def table(self, title: str, columns: List[str], rows: List[List[Any]]):
        if RICH_AVAILABLE:
            table = Table(title=title, box=box.ROUNDED)
            for col in columns:
                table.add_column(col, style='cyan' if col == columns[0] else 'white')
            for row in rows:
                table.add_row(*[str(c) for c in row])
            self._console.print(table)
        else:
            print(f"\n=== {title} ===")
            header = ' | '.join(columns)
            print(header)
            print('-' * len(header))
            for row in rows:
                print(' | '.join(str(c) for c in row))
            print()

    def panel(self, title: str, content: str):
        if RICH_AVAILABLE:
            self._console.print(Panel(content, title=title, border_style='blue'))
        else:
            print(f"\n--- {title} ---\n{content}\n---")

    def progress(self, total: int = 0) -> Optional[Any]:
        if RICH_AVAILABLE:
            return Progress(
                SpinnerColumn(),
                TextColumn('[progress.description]{task.description}'),
                BarColumn(),
                TextColumn('[progress.percentage]{task.percentage:>3.0f}%'),
                console=self._console,
                transient=True
            )
        return None

    def banner(self):
        banner = r"""
    ╔═══╗  ╔╗  ╔╗     ╔╗
    ║╔══╝  ║║  ║║     ║║
    ║╚══╗  ║║  ║║     ║║
    ║╔══╝  ║║  ║║     ║║
    ║║     ║╚══╝╚══╗  ║╚══╗
    ╚╝     ╚═══════╝  ╚═══╝
    Multi-Layer Security Bypass Framework
    """
        if RICH_AVAILABLE:
            self._console.print(f'[bold cyan]{banner}[/bold cyan]')
        else:
            print(banner)

    def divider(self, char: str = '='):
        if RICH_AVAILABLE:
            self._console.rule(style='dim')
        else:
            print(char * 60)

    def json_output(self, data: Dict):
        import json
        if RICH_AVAILABLE:
            self._console.print(Syntax(json.dumps(data, indent=2), 'json'))
        else:
            print(json.dumps(data, indent=2))

    def tree_view(self, label: str, children: List[str]):
        if RICH_AVAILABLE:
            tree = Tree(label)
            for child in children:
                tree.add(child)
            self._console.print(tree)
        else:
            print(f'{label}:')
            for child in children:
                print(f'  ├── {child}')
