"""Colours and small Rich renderers shared by every TUI section."""
from rich.text import Text

BG = "#000000"
FG = "#d0d0d0"
BRIGHT = "#ffffff"
MUTED = "#8a8a8a"
DIM = "#5f5f5f"
FOCUS = "#6c9bd2"

SEV = {"critical": "#f2473f", "high": "#f7931e", "medium": "#f5d327", "low": "#1fb6c9", "info": "#9a9a9a"}
RESULT = {"detected": "#3fbf6f", "silent": "#f2473f", "missing": "#f7931e", "blocked": "#1fb6c9",
          "expected": "#9a9a9a"}
VERDICT = {"proven": "#f2473f", "metered": "#f7931e", "mirror_only": "#f5d327", "not_proven": "#5f5f5f"}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def label(text: str) -> Text:
    return Text(text.upper(), style=MUTED)


def segbar(counts: list[tuple[int, str]], width: int = 24) -> Text:
    """Stacked bar: list of (count, colour), scaled to width cells."""
    total = sum(c for c, _ in counts) or 1
    out, used = Text(), 0
    for i, (c, colour) in enumerate(counts):
        n = round(c * width / total) if i < len(counts) - 1 else width - used
        n = max(0, min(n, width - used))
        out.append("▆" * n, style=colour)
        used += n
    return out


def ratio_bar(value: int, total: int, width: int = 18, colour: str = "#9a9a9a") -> Text:
    n = round(value * width / total) if total else 0
    t = styled("▆" * n, colour)
    t.append("─" * (width - n), style=DIM)
    return t


def hbar(value: int, maximum: int, width: int, colour: str) -> Text:
    n = round(value * width / maximum) if maximum else 0
    t = styled("▆" * n, colour)
    t.append("─" * (width - n), style=DIM)
    return t


def styled(text: str, style: str = "", nowrap: bool = False) -> Text:
    """Text with a styled span. Text(x, style=...) would style everything appended later too."""
    t = Text(no_wrap=nowrap, overflow="ellipsis" if nowrap else "fold")
    t.append(text, style=style)
    return t


def square(colour: str) -> Text:
    return styled("■ ", colour)


def keybar(pairs: list[tuple[str, str]]) -> Text:
    t = Text()
    for k, desc in pairs:
        t.append(f" {k} ", style=f"bold {BRIGHT}")
        t.append(f"{desc}  ", style=MUTED)
    return t
