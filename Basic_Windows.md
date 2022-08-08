# Basic Windows Commands and Tools for Potential Exploitation

## Environment

To see all environment variables set within a shell:

&nbsp; &nbsp; ``C:\> set``

To see specific variables:

&nbsp; &nbsp; ``C:\> set [variables]``

Linux equal to "whoami":

&nbsp; &nbsp;``C:\> set username``

Show path to executables:

&nbsp; &nbsp;``C:\> set path``

## File System

To search for a file in the filesystem:

&nbsp; &nbsp;``C:\> dir /b /s [directory]\[file]``

Example

&nbsp; &nbsp;``C:\> dir /b /s %systemroot%\hosts``

## Accounts and Groups

Local users:

&nbsp; &nbsp; ``C:\> net user``

Local Groups:

&nbsp; &nbsp;``C:\> net localgroup``

Members of Local Admin group:

&nbsp; &nbsp;``C:\> net localgroup administrators``

Add user:

&nbsp; &nbsp;``C:\> net user [logon_name] [password] /add``

Add user to local admin group:

&nbsp; &nbsp;``C:\> net localgroup administrators [logon_name] /add``

Domain User:

&nbsp; &nbsp;``C:\> net user USERNAME /DOMAIN``

List All Domain Users:

&nbsp; &nbsp;``C:\> net user /DOMAIN``
