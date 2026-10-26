"""
FSV — Web Vulnerability Scanner & MCP Security Tool
====================================================

A defensive security scanner in the spirit of OWASP ZAP / Nikto, exposed as an
MCP server so AI agents can run authorized assessments and produce remediation
reports.

Use ONLY against systems you own or are explicitly authorized to test.
"""

__version__ = "2.2.1"
__author__  = "twayst0 (tways)"
__license__ = "AGPL-3.0-only (commercial licences available)"

BANNER = r"""
  ███████╗███████╗██╗   ██╗
  ██╔════╝██╔════╝██║   ██║   Web Vulnerability Scanner
  █████╗  ███████╗██║   ██║   + MCP Security Toolkit
  ██╔══╝  ╚════██║╚██╗ ██╔╝   v{version}
  ██║     ███████║ ╚████╔╝
  ╚═╝     ╚══════╝  ╚═══╝      authorized testing only
""".format(version=__version__)
