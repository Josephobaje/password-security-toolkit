"""Password Security Toolkit.

A privacy-first command-line toolkit for:

* analysing password strength (entropy, patterns, common-password checks),
* checking passwords against the Have I Been Pwned *Pwned Passwords* corpus
  using k-anonymity (only a 5-character SHA-1 prefix ever leaves your machine),
* generating cryptographically secure passwords and passphrases.
"""

from pwtool.breach import BreachCheckError, BreachResult, check_pwned
from pwtool.generator import generate_passphrase, generate_password
from pwtool.strength import StrengthReport, analyze

__all__ = [
    "BreachCheckError",
    "BreachResult",
    "StrengthReport",
    "__version__",
    "analyze",
    "check_pwned",
    "generate_passphrase",
    "generate_password",
]

__version__ = "1.0.0"
