"""Keep accessible display labels when the installed Streamlit API supports them."""
from inspect import signature


def alt_text(command, text):
    """Supply alt only to commands that explicitly declare that keyword."""
    return {"alt": text} if "alt" in signature(command).parameters else {}
