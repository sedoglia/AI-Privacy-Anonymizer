# Runtime hook: pre-seed tiktoken encoding constructors.
#
# Inside a PyInstaller onefile archive, pkgutil.iter_modules() cannot walk
# namespace package paths (tiktoken_ext is a namespace package). As a result,
# tiktoken._find_constructors() finds zero plugins and raises
# "Unknown encoding o200k_base".
#
# Fix: import tiktoken_ext.openai_public directly and seed ENCODING_CONSTRUCTORS
# before any call to tiktoken.get_encoding().
import tiktoken.registry as _registry
import tiktoken_ext.openai_public as _openai_public

with _registry._lock:
    if _registry.ENCODING_CONSTRUCTORS is None:
        _registry.ENCODING_CONSTRUCTORS = dict(_openai_public.ENCODING_CONSTRUCTORS)
