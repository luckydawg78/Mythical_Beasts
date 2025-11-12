from datetime import datetime


def log(*args, level: str = None):
    """
    Simple logger helper.

    Usage:
      log("a message")
      log("error", "Scan failed.")    # level followed by message
      log("a message", level="warning")

    Prints lines like: [HH:MM:SS] [LEVEL] message
    """
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Default level
    lvl = "INFO"
    msg = ""

    if level:
        # explicit keyword level provided
        lvl = str(level).upper()
        msg = " ".join(map(str, args)) if args else ""
    else:
        # positional handling: either (message,) or (level, message, ...)
        if len(args) == 0:
            msg = ""
        elif len(args) == 1:
            msg = args[0]
        else:
            first = str(args[0]).lower()
            if first in ("debug", "info", "warning", "error", "critical"):
                lvl = first.upper()
                msg = args[1]
            else:
                # join all args into a single message
                msg = " ".join(map(str, args))

    print(f"[{timestamp}] [{lvl}] {msg}")